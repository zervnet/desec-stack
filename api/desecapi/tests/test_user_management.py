"""
This module tests deSEC's user management.

The tests are separated into two categories, where
(a) the client has an associated user account and
(b) does not have an associated user account.

This involves testing five separate endpoints:
(1) Registration endpoint,
(2) Reset password endpoint,
(3) Change email address endpoint,
(4) delete user endpoint, and
(5) verify endpoint.
"""
import re
from datetime import timedelta

from django.core import mail
from django.utils.datetime_safe import datetime
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from desecapi.models import User
from desecapi.tests.base import DesecTestCase


class UserManagementClient(APIClient):

    def register(self, email, password, invitation):
        return self.post(reverse('v1:register'), {
            'email': email,
            'password': password,
            'invitation': invitation,
        })

    def reset_password(self, email):
        return self.post(reverse('v1:reset-password'), {
            'email': email,
        })

    def change_email(self, email, password, new_email):
        return self.post(reverse('v1:change-email'), {
            'email': email,
            'password': password,
            'new_email': new_email,
        })

    def delete_account(self, email, password):
        return self.post(reverse('v1:delete-account'), {
            'email': email,
            'password': password,
        })

    def verify(self, verification_code, new_password=None):
        data = {'verification_code': verification_code}
        if new_password:
            data['new_password'] = new_password
        return self.post(reverse('v1:verify'), data)


class UserManagementTestCase(DesecTestCase):

    client_class = UserManagementClient

    def _generate_invitation(self):
        # TODO fill in
        pass

    def _generate_registration_validation_code(self, email, new_email, expiry_time=None):
        # TODO fill in
        pass

    def _generate_change_email_validation_code(self, email, new_email, expiry_time=None):
        # TODO fill in
        pass

    def _generate_reset_password_validation_code(self, email, new_password, expiry_time=None):
        # TODO fill in
        pass

    def _generate_delete_account_validation_code(self, email, expiry_time=None):
        # TODO fill in
        pass

    def register_user(self, email=None, password=None, invitation=None):
        email = email if email is not None else self.random_username()
        password = password if password is not None else self.random_password()
        invitation = invitation if invitation is not None else self._generate_invitation()
        return email, password, self.client.register(email, password, invitation)

    def reset_password(self, email):
        return self.client.reset_password(email)

    def change_email(self, email, password, new_email):
        return self.client.change_email(email, password, new_email)

    def delete_account(self, email, password):
        return self.client.delete_account(email, password)

    def verify(self, verification_code, new_password=None):
        return self.client.verify(verification_code, new_password)

    def assertPassword(self, email, password):
        self.assertTrue(User.objects.get(email=email).check_password(password),
                        'Expected user password to be %s, but was wrong.')

    def assertUserExists(self, email):
        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            self.fail('Expected user %s to exist, but did not.' % email)

    def assertUserDoesNotExist(self, email):
        # noinspection PyTypeChecker
        with self.assertRaises(User.DoesNotExist):
            User.objects.get(email=email)

    def assertNoEmailSent(self):
        self.assertFalse(mail.outbox, "Expected no email to be sent, but %i were sent. First subject line is '%s'." %
                         (len(mail.outbox), mail.outbox[0].subject))

    def assertEmailSent(self, subject_contains='', body_contains='', recipient=None, reset=True, pattern=None):
        total = 1
        index = 0
        self.assertEqual(len(mail.outbox), total, "Expected %i message in the outbox, but found %i." %
                         (total, len(mail.outbox)))
        email = mail.outbox[index]
        self.assertTrue(subject_contains in email.subject,
                        "Expected '%s' in the email subject, but found '%s'" %
                        (subject_contains, email.subject))
        self.assertTrue(body_contains in email.body,
                        "Expected '%s' in the email body, but found '%s'" %
                        (body_contains, email.body))
        if recipient is not None:
            if isinstance(recipient, list):
                self.assertListEqual(recipient, email.recipients())
            else:
                self.assertIn(recipient, email.recipients())
        body = email.body
        if reset:
            mail.outbox = []
        return body if not pattern else re.match(pattern, body).group(0)

    def assertRegistrationEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='deSEC',
            body_contains='welcome',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertResetPasswordEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Password reset',
            body_contains='verification code',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertChangeEmailVerificationEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Email address verification',
            body_contains='verification code',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertChangeEmailNotificationEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Email address changed',
            body_contains='was changed',
            recipient=[recipient],
            reset=reset,
        )

    def assertDeleteAccountEmail(self, recipient, reset=True):
        return self.assertEmailSent(
            subject_contains='Delete your account',
            body_contains='verification code',
            recipient=[recipient],
            reset=reset,
            pattern=r'verification code: ([^\s]*)',
        )

    def assertRegistrationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Welcome! Please check your mailbox.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assertRegistrationFailureInvitationRequiredResponse(self, response):
        self.assertContains(
            response=response,
            text="Invitation only. Please contact the support to get a valid invitation.",
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    def assertRegistrationFailurePasswordRequiredResponse(self, response):
        self.assertContains(
            response=response,
            text="Password must be given.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertRegistrationVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Account activated. Please log in at",
            status_code=status.HTTP_200_OK
        )

    def assertResetPasswordSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Please check your mailbox to confirm password change.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assertResetPasswordVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Password changed.",
            status_code=status.HTTP_200_OK
        )

    def assertChangeEmailSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Please check your mailbox to confirm email address change.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assert401InvalidPasswordResponse(self, response):
        return self.assertContains(
            response=response,
            text="Invalid password.",
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    def assertChangeEmailFailureAddressTakenResponse(self, response):
        return self.assertChangeEmailSuccessResponse(response)

    def assertChangeEmailFailureSameAddressResponse(self, response):
        return self.assertContains(
            response=response,
            text="Email address unchanged.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertChangeEmailVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="email address changed",
            status_code=status.HTTP_200_OK
        )

    def assertChangeEmailVerificationFailureChangePasswordResponse(self, response):
        return self.assertContains(
            response=response,
            text="Password change not authorized. Please use a password reset validation code.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def assertDeleteAccountSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="Please check your mailbox to confirm account deletion.",
            status_code=status.HTTP_202_ACCEPTED
        )

    def assertDeleteAccountVerificationSuccessResponse(self, response):
        return self.assertContains(
            response=response,
            text="All your data was deleted. Bye bye, see you soon! <3",
            status_code=status.HTTP_200_OK
        )

    def assertVerificationFailureInvalidCodeResponse(self, response):
        return self.assertContains(
            response=response,
            text="Invalid verification code.",
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    def assertVerificationFailureUnknownUserResponse(self, response):
        return self.assertContains(
            response=response,
            text="Account was deleted.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    def _test_registration(self, email=None, password=None, invitation=None):
        email, password, response = self.register_user(email, password, invitation)
        self.assertRegistrationSuccessResponse(response)
        verification_code = self.assertRegistrationEmail(email)
        self.assertRegistrationVerificationSuccessResponse(self.verify(verification_code))
        self.assertUserExists(email)
        self.assertPassword(email, password)
        return email, password

    def _test_reset_password(self, email):
        new_password = self.random_password()
        self.assertResetPasswordSuccessResponse(self.reset_password(email))
        verification_code = self.assertResetPasswordEmail(email)
        self.assertResetPasswordVerificationSuccessResponse(self.verify(verification_code, new_password))
        self.assertPassword(email, new_password)
        return new_password

    def _test_change_email(self, email, password):
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(self.change_email(email, password, new_email))
        verification_code = self.assertChangeEmailVerificationEmail(new_email)
        self.assertChangeEmailVerificationSuccessResponse(self.verify(verification_code))
        self.assertChangeEmailNotificationEmail(email)
        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(email)
        return new_email

    def _test_delete_account(self, email, password):
        self.assertDeleteAccountSuccessResponse(self.delete_account(email, password))
        verification_code = self.assertDeleteAccountEmail(email)
        self.assertDeleteAccountVerificationSuccessResponse(self.verify(verification_code))
        self.assertUserDoesNotExist(email)


class UserLifeCycleTestCase(UserManagementTestCase):

    def test_life_cycle(self):
        email, password = self._test_registration()
        password = self._test_reset_password(email)
        email = self._test_change_email(email, password)
        self._test_delete_account(email, password)


class NoUserAccountTestCase(UserLifeCycleTestCase):

    def test_registration(self):
        self._test_registration()

    def test_registration_known_account(self):
        email, _ = self._test_registration()
        self.assertRegistrationSuccessResponse(self.register_user(email, self.random_password()))
        self.assertNoEmailSent()

    def test_registration_invitation_required(self):
        email = self.random_username()
        self.assertRegistrationFailureInvitationRequiredResponse(
            response=self.register_user(email=email, invitation='foobar')
        )
        self.assertNoEmailSent()
        self.assertUserDoesNotExist(email)

    def test_registration_password_required(self):
        email = self.random_username()
        self.assertRegistrationFailurePasswordRequiredResponse(
            response=self.register_user(email=email, password='')
        )
        self.assertNoEmailSent()
        self.assertUserDoesNotExist(email)

    def test_registration_spam_protection(self):
        email = self.random_username()
        self.assertRegistrationSuccessResponse(
            response=self.register_user(email=email)
        )
        self.assertRegistrationEmail(email)
        for _ in range(5):
            self.assertRegistrationSuccessResponse(
                response=self.register_user(email=email)
            )
            self.assertNoEmailSent()


class OtherUserAccountTestCase(UserManagementTestCase):

    def setUp(self):
        super().setUp()
        self.other_email, self.other_password = self._test_registration()

    def test_change_email_wrong_password(self):
        self.assert401InvalidPasswordResponse(
            response=self.change_email(self.other_email, self.random_password(), self.random_username())
        )
        self.assertNoEmailSent()
        self.assertPassword(self.other_email, self.other_password)

    def test_change_email_unknown_user(self):
        unknown_email = self.random_username()
        self.assert401InvalidPasswordResponse(
            response=self.change_email(unknown_email, self.random_password(), self.random_username())
        )
        self.assertNoEmailSent()
        self.assertUserDoesNotExist(unknown_email)

    def test_reset_password_unknown_user(self):
        # TODO this does not account for timing side-channel information
        self.assertResetPasswordSuccessResponse(
            response=self.reset_password(self.random_username())
        )
        self.assertNoEmailSent()

    def test_reset_password_spam_protection(self):
        self.assertResetPasswordSuccessResponse(
            response=self.reset_password(self.other_email)
        )
        self.assertResetPasswordEmail(self.other_email)
        for _ in range(5):
            self.assertResetPasswordSuccessResponse(
                response=self.reset_password(self.other_email)
            )
            self.assertNoEmailSent()

    def test_delete_account_wrong_password(self):
        self.assert401InvalidPasswordResponse(
            response=self.delete_account(self.other_email, self.random_password())
        )
        self.assertNoEmailSent()
        self.assertPassword(self.other_email, self.other_password)

    def test_delete_account_unknown_user(self):
        self.assert401InvalidPasswordResponse(
            response=self.delete_account(self.random_username(), self.other_password)
        )
        self.assertNoEmailSent()
        self.assertPassword(self.other_email, self.other_password)

    def test_verify_registration(self):
        # TODO what to do if token expired and account wasn't activated?
        just_passed = datetime.now() - timedelta(seconds=1)
        for verification_code in [
            'something smart here',  # TODO make it actually smart
            'fake verification code',
            self._generate_registration_validation_code(self.random_username(), just_passed),
        ]:
            self.assertVerificationFailureInvalidCodeResponse(
                self.verify(verification_code, new_password=self.random_password()))
            self.assertNoEmailSent()
            self.assertPassword(self.other_email, self.other_password)

    def test_verify_change_other_password(self):
        just_passed = datetime.now() - timedelta(seconds=1)
        new_password = self.random_password()
        for verification_code in [
            'something smart here',  # TODO make it actually smart
            'fake verification code',
            self._generate_reset_password_validation_code(self.other_email, new_password, just_passed),
            self._generate_reset_password_validation_code(self.random_username(), new_password),
        ]:
            self.assertVerificationFailureInvalidCodeResponse(
                self.verify(verification_code, new_password=self.random_password()))
            self.assertNoEmailSent()
            self.assertPassword(self.other_email, self.other_password)

    def test_verify_change_other_email(self):
        just_passed = datetime.now() - timedelta(seconds=1)
        new_email = self.random_username()
        for verification_code in [
            'something smart here',  # TODO make it actually smart
            'fake verification code',
            self._generate_change_email_validation_code(self.other_email, new_email, expiry_time=just_passed),
            self._generate_change_email_validation_code(self.random_username(), new_email),
        ]:
            self.assertVerificationFailureInvalidCodeResponse(
                self.verify(verification_code))
            self.assertNoEmailSent()
            self.assertUserExists(self.other_email)

    def test_verify_delete_other_account(self):
        just_passed = datetime.now() - timedelta(seconds=1)
        for verification_code in [
            'something smart here',  # TODO make it actually smart
            'fake verification code',
            self._generate_delete_account_validation_code(self.other_email, expiry_time=just_passed),
            self._generate_delete_account_validation_code(self.random_username()),
        ]:
            self.assertVerificationFailureInvalidCodeResponse(
                self.verify(verification_code))
            self.assertNoEmailSent()
            self.assertUserExists(self.other_email)


class HasUserAccountTestCase(UserManagementTestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.email = None
        self.password = None

    def setUp(self):
        super().setUp()
        self.email, self.password = self._test_registration()

    def _start_reset_password(self):
        self.assertResetPasswordSuccessResponse(
            response=self.reset_password(self.email)
        )
        return self.assertResetPasswordEmail(self.email)

    def _start_change_email(self):
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(
            response=self.change_email(self.email, self.password, new_email)
        )
        return self.assertChangeEmailVerificationEmail(new_email), new_email

    def _start_delete_account(self):
        self.assertDeleteAccountSuccessResponse(self.delete_account(self.email, self.password))
        return self.assertDeleteAccountEmail(self.email)

    def _finish_reset_password(self, verification_code):
        new_password = self.random_password()
        self.assertResetPasswordVerificationSuccessResponse(
            response=self.verify(verification_code, new_password)
        )
        return new_password

    def _finish_change_email(self, verification_code):
        self.assertChangeEmailVerificationSuccessResponse(
            response=self.verify(verification_code)
        )
        self.assertChangeEmailNotificationEmail(self.email)

    def _finish_delete_account(self, verification_code):
        self.assertDeleteAccountVerificationSuccessResponse(self.verify(verification_code))
        self.assertUserDoesNotExist(self.email)

    def test_reset_password(self):
        self._test_reset_password(self.email)

    def test_reset_password_multiple_times(self):
        for _ in range(3):
            self._test_reset_password(self.email)

    def test_reset_password_during_change_email_interleaved(self):
        reset_password_verification_code = self._start_reset_password()
        change_email_verification_code, new_email = self._start_change_email()
        new_password = self._finish_reset_password(reset_password_verification_code)
        self._finish_change_email(change_email_verification_code)

        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(self.email)
        self.assertPassword(new_email, new_password)

    def test_reset_password_during_change_email_nested(self):
        change_email_verification_code, new_email = self._start_change_email()
        reset_password_verification_code = self._start_reset_password()
        new_password = self._finish_reset_password(reset_password_verification_code)
        self._finish_change_email(change_email_verification_code)

        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(self.email)
        self.assertPassword(new_email, new_password)

    def test_reset_password_validation_unknown_user(self):
        verification_code = self._start_reset_password()
        self._test_delete_account(self.email, self.password)
        self.assertVerificationFailureUnknownUserResponse(
            response=self.verify(verification_code)
        )
        self.assertNoEmailSent()

    def test_change_email(self):
        self._test_change_email(self.email, self.password)

    def test_change_email_multiple_times(self):
        email = self.email
        for _ in range(3):
            email = self._test_change_email(email, self.password)

    def test_change_email_user_exists(self):
        known_email, _ = self._test_registration()
        self.assertChangeEmailFailureAddressTakenResponse(
            response=self.change_email(self.email, self.password, known_email)
        )

    def test_change_email_verification_user_exists(self):
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(self.change_email(self.email, self.password, new_email))
        verification_code = self.assertChangeEmailVerificationEmail(new_email)
        new_email, new_password = self._test_registration(new_email)
        self.assertChangeEmailFailureAddressTakenResponse(
            response=self.verify(verification_code)
        )
        self.assertUserExists(self.email)
        self.assertPassword(self.email, self.password)
        self.assertUserExists(new_email)
        self.assertPassword(new_email, new_password)

    def test_change_email_verification_change_password(self):
        new_email = self.random_username()
        self.assertChangeEmailSuccessResponse(self.change_email(self.email, self.password, new_email))
        verification_code = self.assertChangeEmailVerificationEmail(new_email)
        self.assertChangeEmailVerificationFailureChangePasswordResponse(
            response=self.verify(verification_code, self.random_password())
        )
        self.assertUserExists(self.email)
        self.assertUserDoesNotExist(new_email)
        self.assertPassword(self.email, self.password)
        self.assertChangeEmailVerificationSuccessResponse(
            response=self.verify(verification_code)
        )
        self.assertUserDoesNotExist(self.email)
        self.assertUserExists(new_email)
        self.assertPassword(self.email, self.password)

    def test_change_email_same_email(self):
        self.assertChangeEmailFailureSameAddressResponse(
            response=self.change_email(self.email, self.password, self.email)
        )
        self.assertUserExists(self.email)

    def test_change_email_during_reset_password_interleaved(self):
        change_email_verification_code, new_email = self._start_change_email()
        reset_password_verification_code = self._start_reset_password()
        self._finish_change_email(change_email_verification_code)
        new_password = self._finish_reset_password(reset_password_verification_code)

        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(self.email)
        self.assertPassword(new_email, new_password)

    def test_change_email_during_reset_password_nested(self):
        reset_password_verification_code = self._start_reset_password()
        change_email_verification_code, new_email = self._start_change_email()
        self._finish_change_email(change_email_verification_code)
        new_password = self._finish_reset_password(reset_password_verification_code)

        self.assertUserExists(new_email)
        self.assertUserDoesNotExist(self.email)
        self.assertPassword(new_email, new_password)

    def test_change_email_nested(self):
        verification_code_1, new_email_1 = self._start_change_email()
        verification_code_2, new_email_2 = self._start_change_email()

        self._finish_change_email(verification_code_2)
        self.assertUserDoesNotExist(self.email)
        self.assertUserDoesNotExist(new_email_1)
        self.assertUserExists(new_email_2)

        self._finish_change_email(verification_code_1)
        self.assertUserDoesNotExist(self.email)
        self.assertUserExists(new_email_1)
        self.assertUserDoesNotExist(new_email_2)

    def test_change_email_interleaved(self):
        verification_code_1, new_email_1 = self._start_change_email()
        verification_code_2, new_email_2 = self._start_change_email()

        self._finish_change_email(verification_code_1)
        self.assertUserDoesNotExist(self.email)
        self.assertUserExists(new_email_1)
        self.assertUserDoesNotExist(new_email_2)

        self._finish_change_email(verification_code_2)
        self.assertUserDoesNotExist(self.email)
        self.assertUserDoesNotExist(new_email_1)
        self.assertUserExists(new_email_2)

    def test_change_email_validation_unknown_user(self):
        verification_code, new_email = self._start_change_email()
        self._test_delete_account(self.email, self.password)
        self.assertVerificationFailureUnknownUserResponse(
            response=self.verify(verification_code)
        )
        self.assertNoEmailSent()

    def test_delete_account_validation_unknown_user(self):
        verification_code = self._start_delete_account()
        self._test_delete_account(self.email, self.password)
        self.assertVerificationFailureUnknownUserResponse(
            response=self.verify(verification_code)
        )
        self.assertNoEmailSent()
