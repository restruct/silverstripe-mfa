<?php

namespace SilverStripe\MFA\Tests\Authenticator;

use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\MFA\Authenticator\ChangePasswordHandler;
use SilverStripe\MFA\Service\MethodRegistry;
use SilverStripe\MFA\Tests\Stub\BasicMath\Method;
use SilverStripe\Security\Member;

/**
 * Regression tests for CVE-2026-55186: in the password reset flow a member with MFA set up could
 * change their password and get logged in without completing MFA, by posting the change password
 * form directly.
 *
 * Each test walks the real reset flow: the reset link (?m=&t=) puts the member's AutoLoginHash in
 * the session, then the form is posted to doChangePassword(). Except in the endpoint test, the
 * completed MFA check is simulated by setting the session values verifyMFACheck() sets.
 */
class ChangePasswordHandlerResetTest extends FunctionalTest
{
    protected static $fixture_file = 'ChangePasswordHandlerResetTest.yml';

    private const NEW_PASSWORD = 'Changed-Passw0rd-1234';

    protected function setUp(): void
    {
        parent::setUp();
        Config::modify()->set(MethodRegistry::class, 'methods', [Method::class]);
    }

    public function testPostWithoutMfaCheckDoesNotChangePasswordOrLogIn()
    {
        $member = $this->objFromFixture(Member::class, 'alice');
        $passwordBefore = $member->Password;

        $this->openResetLink($member);
        $response = $this->postNewPassword();

        # Sent back to changepassword(), which shows the MFA check (FunctionalTest follows the redirect)
        $this->assertStringContainsString('id="mfa-app"', $response->getBody(), 'MFA screen should be displayed');
        $this->assertSame($passwordBefore, Member::get()->byID($member->ID)->Password, 'password must not change');
        $this->assertEmpty($this->session()->get('loggedInAs'), 'member must not be logged in');
    }

    public function testPostAfterMfaCheckForThisMemberChangesPasswordAndLogsIn()
    {
        $member = $this->objFromFixture(Member::class, 'alice');
        $passwordBefore = $member->Password;

        $this->openResetLink($member);
        $this->markMfaVerifiedFor($member);
        $this->postNewPassword();

        $this->assertNotSame($passwordBefore, Member::get()->byID($member->ID)->Password, 'password must change');
        $this->assertEquals($member->ID, $this->session()->get('loggedInAs'));
    }

    public function testMfaCheckCompletedForAnotherMemberDoesNotCount()
    {
        $alice = $this->objFromFixture(Member::class, 'alice');
        $bob = $this->objFromFixture(Member::class, 'bob');
        $passwordBefore = $bob->Password;

        # MFA completed for alice's reset, then bob's reset link opened in the same session
        $this->openResetLink($alice);
        $this->markMfaVerifiedFor($alice);
        $this->openResetLink($bob);
        $response = $this->postNewPassword();

        $this->assertStringContainsString('id="mfa-app"', $response->getBody(), 'MFA screen should be displayed');
        $this->assertSame($passwordBefore, Member::get()->byID($bob->ID)->Password, 'password must not change');
        $this->assertEmpty($this->session()->get('loggedInAs'), 'member must not be logged in');
        $this->assertEmpty(
            $this->session()->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD),
            'the check made for another member is forgotten'
        );
    }

    public function testMfaCheckCompletedForAnotherMemberIsAskedAgainOnTheForm()
    {
        $alice = $this->objFromFixture(Member::class, 'alice');
        $bob = $this->objFromFixture(Member::class, 'bob');

        $this->openResetLink($alice);
        $this->markMfaVerifiedFor($alice);
        $this->openResetLink($bob);
        $body = $this->get('Security/changepassword')->getBody();

        $this->assertStringContainsString('id="mfa-app"', $body, 'MFA screen should be displayed');
        $this->assertStringNotContainsString('NewPassword1', $body, 'password form should not be shown');
    }

    public function testRealMfaCheckThroughTheEndpointsAllowsTheReset()
    {
        $member = $this->objFromFixture(Member::class, 'alice');
        $passwordBefore = $member->Password;

        $this->openResetLink($member);
        # The MFA app's own calls: start the check, then send the answer
        $start = $this->get('Security/changepassword/mfa/login/basic-math');
        $this->assertSame(200, $start->getStatusCode(), $start->getBody());
        $numbers = json_decode($start->getBody(), true)['numbers'];
        $verify = $this->post(
            'Security/changepassword/mfa/login/basic-math',
            [],
            ['Content-Type' => 'application/json'],
            null,
            json_encode(['answer' => array_sum($numbers)])
        );
        $this->assertSame(200, $verify->getStatusCode(), $verify->getBody());
        $this->assertEquals(
            $member->ID,
            $this->session()->get(ChangePasswordHandler::MFA_VERIFIED_MEMBER_ID),
            'the completed check is recorded for this member'
        );

        $this->postNewPassword();

        $this->assertNotSame($passwordBefore, Member::get()->byID($member->ID)->Password, 'password must change');
        $this->assertEquals($member->ID, $this->session()->get('loggedInAs'));
    }

    public function testMemberWithoutMfaCanStillResetTheirPassword()
    {
        $member = $this->objFromFixture(Member::class, 'carol');
        $passwordBefore = $member->Password;

        $this->openResetLink($member);
        $this->postNewPassword();

        $this->assertNotSame($passwordBefore, Member::get()->byID($member->ID)->Password, 'password must change');
        $this->assertEquals($member->ID, $this->session()->get('loggedInAs'));
    }

    /**
     * Follow a reset link the way the email does, so the framework stores the AutoLoginHash itself.
     */
    private function openResetLink(Member $member): void
    {
        $token = $member->generateAutologinTokenAndStoreHash();
        $this->get("Security/changepassword?m={$member->ID}&t={$token}");
        $this->assertNotEmpty($this->session()->get('AutoLoginHash'), 'reset link should put the hash in the session');
    }

    /**
     * The session state verifyMFACheck() leaves after a successful check for this member.
     */
    private function markMfaVerifiedFor(Member $member): void
    {
        $this->session()->set(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD, true);
        $this->session()->set(ChangePasswordHandler::MFA_VERIFIED_MEMBER_ID, $member->ID);
    }

    private function postNewPassword(): HTTPResponse
    {
        return $this->post('Security/changepassword/ChangePasswordForm', [
            'NewPassword1' => self::NEW_PASSWORD,
            'NewPassword2' => self::NEW_PASSWORD,
            'action_doChangePassword' => 1,
        ]);
    }
}
