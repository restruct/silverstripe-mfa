<?php

declare(strict_types=1);

namespace SilverStripe\MFA\Authenticator;

use LogicException;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Exception\InvalidMethodException;
use SilverStripe\MFA\Extension\MemberExtension;
use SilverStripe\MFA\RequestHandler\BaseHandlerTrait;
use SilverStripe\MFA\RequestHandler\VerificationHandlerTrait;
use SilverStripe\MFA\Service\MethodRegistry;
use SilverStripe\MFA\Service\SchemaGenerator;
use SilverStripe\MFA\Store\StoreInterface;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\ChangePasswordHandler as BaseChangePasswordHandler;
use SilverStripe\Security\Security;
use Throwable;

/**
 * Extends the "MemberAuthenticator version of the ChangePasswordHandler in order to allow MFA to be
 * inserted into the flow when an AutoLoginHash is being used  - that is when the user has clicked a
 * reset password link in an email after using the "forgot password" functionality.
 * When an "auto login" is not being used (a user is already logged in), it is existing functionality
 * to ask a user for their password before allowing a change - so this flow does not require MFA.
 */
class ChangePasswordHandler extends BaseChangePasswordHandler
{
    use BaseHandlerTrait;
    use VerificationHandlerTrait;

    /**
     * Session key used to track whether multi-factor authentication has been verified during a change password
     * request flow.
     *
     * @var string
     */
    public const MFA_VERIFIED_ON_CHANGE_PASSWORD = 'MultiFactorAuthenticated';

    /**
     * Session key holding the ID of the member the multi-factor check was completed for, so a check
     * completed for one member does not count for another reset link opened in the same session
     * (CVE-2026-55186).
     *
     * @var string
     */
    public const MFA_VERIFIED_MEMBER_ID = 'MultiFactorAuthenticatedMemberID';

    private static $url_handlers = [
        'GET mfa/schema' => 'getSchema', // Provides details about existing registered methods, etc.
        'GET mfa/login/$Method' => 'startMFACheck', // Initiates login process for $Method
        'POST mfa/login/$Method' => 'verifyMFACheck', // Verifies login via $Method
        'GET mfa' => 'mfa', // Renders the MFA Login Page to init the app
    ];

    private static $allowed_actions = [
        'changepassword',
        'mfa',
        'getSchema',
        'startMFACheck',
        'verifyMFACheck',
    ];

    private static $dependencies = [
        'Logger' => '%$' . LoggerInterface::class . '.mfa',
    ];

    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Respond with the given array as a JSON response
     *
     * @param array $response
     * @param int $code The HTTP response code to set on the response
     * @return HTTPResponse
     */
    protected function jsonResponse(array $response, int $code = 200): HTTPResponse
    {
        return HTTPResponse::create(json_encode($response))
            ->addHeader('Content-Type', 'application/json')
            ->setStatusCode($code);
    }

    /**
     * Supply JavaScript application configuration details, required for an MFA check
     *
     * @return HTTPResponse
     */
    public function getSchema(): HTTPResponse
    {
        try {
            $member = $this->getStore()->getMember();
            $schema = SchemaGenerator::create()->getSchema($member);
            return $this->jsonResponse(
                array_merge($schema, [
                    'endpoints' => [
                        'verify' => $this->Link('mfa/login/{urlSegment}'),
                        'complete' => $this->Link(),
                    ],
                    'shouldRedirect' => false,
                ])
            );
        } catch (Throwable $exception) {
            $this->logger->debug($exception->getMessage());
            // If we don't have a valid member we shouldn't be here...
            return $this->redirectBack();
        }
    }

    /**
     * Render the JavaScript app responsible for initiating an MFA check
     *
     * @return HTTPResponse|array
     */
    public function mfa()
    {
        $store = $this->getStore();
        if (!$store || !$store->getMember()) {
            return $this->redirectBack();
        }

        $this->applyRequirements();

        return [
            'Form' => $this->renderWith($this->getViewerTemplates()),
            'ClassName' => 'mfa',
        ];
    }

    /**
     * Initiates the session for the user attempting to log in, in preparation for an MFA check
     *
     * @param HTTPRequest $request
     * @return HTTPResponse
     * @throws LogicException when no store is available
     */
    public function startMFACheck(HTTPRequest $request): HTTPResponse
    {
        $store = $this->getStore();
        if (!$store) {
            throw new LogicException('Store not found, please create one first.');
        }
        $member = $store->getMember();

        // If we don't have a valid member we shouldn't be here...
        if (!$member) {
            return $this->jsonResponse(['message' => 'Forbidden'], 403);
        }

        $method = $request->param('Method');

        if (empty($method)) {
            return $this->jsonResponse(['message' => 'Invalid request: method not present'], 400);
        }

        // Use the provided trait method for handling login
        $response = $this->createStartVerificationResponse(
            $store,
            Injector::inst()->get(MethodRegistry::class)->getMethodByURLSegment($method)
        );

        // Ensure detail is saved to the store
        $store->save($request);

        return $response;
    }

    /**
     * Checks the MFA JavaScript app input to validate the user attempting to log in
     *
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function verifyMFACheck(HTTPRequest $request): HTTPResponse
    {
        $store = $this->getStore();
        # The store is cleared once the check completes, so read the member first (CVE-2026-55186)
        $member = $store ? $store->getMember() : null;

        try {
            $result = $this->completeVerificationRequest($store, $request);
        } catch (InvalidMethodException $exception) {
            // Invalid method usually means a timeout. A user might be trying to verify before "starting"
            $this->logger->debug($exception->getMessage());
            return $this->jsonResponse(['message' => 'Forbidden'], 403);
        }

        if (!$result->isSuccessful()) {
            return $this->jsonResponse([
                'message' => $result->getMessage(),
            ], 401);
        }

        if (!$this->isVerificationComplete($store)) {
            return $this->jsonResponse([
                'message' => 'Additional authentication required',
            ], 202);
        }

        $request->getSession()->set(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD, true);
        # Bind the completed check to this member (CVE-2026-55186)
        if ($member) {
            $request->getSession()->set(ChangePasswordHandler::MFA_VERIFIED_MEMBER_ID, (int) $member->ID);
        }
        $store->clear($request);

        return $this->jsonResponse([
            'message' => 'Multi-factor authenticated',
        ], 200);
    }

    public function changepassword()
    {
        $this->dropVerificationForOtherMember();

        $session = $this->getRequest()->getSession();
        $hash = $session->get('AutoLoginHash');
        /** @var Member&MemberExtension $member */
        $member = Member::member_from_autologinhash($hash);

        if (
            $hash
            && $member
            && $member->RegisteredMFAMethods()->exists()
            && !$session->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD)
        ) {
            Injector::inst()->create(StoreInterface::class, $member)->save($this->getRequest());
            return $this->mfa();
        }

        return parent::changepassword();
    }

    /**
     * The multi-factor check above runs in changepassword(), which only handles the GET that shows
     * the form. The reset link stores the member's AutoLoginHash in the session before that check
     * runs, so a POST straight to this form action changed the password and logged the member in
     * without it (CVE-2026-55186). Refuse that POST until the member the reset link belongs to has
     * completed the check, and send them back to it.
     *
     * @param array $data
     * @param \SilverStripe\Security\MemberAuthenticator\ChangePasswordForm $form
     * @return HTTPResponse
     */
    public function doChangePassword(array $data, $form)
    {
        $this->dropVerificationForOtherMember();

        # A logged-in member changing their own password passed the check at login, and the parent
        # asks for their current password; only the reset flow is gated.
        $member = $this->getResetMember();
        if (!Security::getCurrentUser()
            && $member
            && $member->RegisteredMFAMethods()->exists()
            && !$this->isVerifiedFor($member)
        ) {
            # Back to changepassword(), which starts the multi-factor check for this member
            return $this->redirect($this->Link());
        }

        return parent::doChangePassword($data, $form);
    }

    /**
     * The member the reset link in this session belongs to, if any.
     *
     * @return Member&MemberExtension|null
     */
    protected function getResetMember(): ?Member
    {
        $hash = $this->getRequest()->getSession()->get('AutoLoginHash');
        if (!$hash) {
            return null;
        }
        return Member::member_from_autologinhash($hash);
    }

    /**
     * Whether the multi-factor check of this session was completed for the given member.
     *
     * @param Member $member
     * @return bool
     */
    protected function isVerifiedFor(Member $member): bool
    {
        $session = $this->getRequest()->getSession();
        return (bool) $session->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD)
            && (int) $session->get(ChangePasswordHandler::MFA_VERIFIED_MEMBER_ID) === (int) $member->ID;
    }

    /**
     * Forget a completed multi-factor check that was not made for the member of the current reset
     * link, so the check in changepassword() (which reads only the flag) asks again.
     */
    protected function dropVerificationForOtherMember(): void
    {
        $session = $this->getRequest()->getSession();
        if (!$session->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD)) {
            return;
        }
        $member = $this->getResetMember();
        if ($member && !$this->isVerifiedFor($member)) {
            $session->clear(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD);
            $session->clear(ChangePasswordHandler::MFA_VERIFIED_MEMBER_ID);
        }
    }

    /**
     * @param LoggerInterface $logger
     * @return $this
     */
    public function setLogger(LoggerInterface $logger): ChangePasswordHandler
    {
        $this->logger = $logger;
        return $this;
    }
}
