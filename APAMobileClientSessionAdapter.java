import androidx.annotation.NonNull;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.mobile.client.AWSMobileClient;
import com.amazonaws.mobile.client.results.Tokens;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.util.CognitoJWTParser;
import com.amplifyframework.auth.AuthException;
import com.amplifyframework.auth.AuthSession;
import com.amplifyframework.auth.cognito.AWSCognitoAuthSession;
import com.amplifyframework.auth.cognito.AWSCognitoUserPoolTokens;
import com.amplifyframework.auth.result.AuthSessionResult;
import com.amplifyframework.core.Consumer;

import org.jetbrains.annotations.NotNull;
import org.json.JSONException;

import java.util.Arrays;
import java.util.List;

/**
 * Created by Arthur on 2020/10/14.
 */
final class APAMobileClientSessionAdapter {
    // Since AWSMobileClient does not categorize its errors in any way, we resort to categorizing its
    // messages here as a temporary hack until we replace it with a fresh implementation of Auth.
    private static final List<String> MOBILE_CLIENT_INVALID_ACCOUNT_MESSAGES = Arrays.asList(
            "getTokens does not support retrieving tokens for federated sign-in",
            "You must be signed-in with Cognito Userpools to be able to use getTokens",
            "Tokens are not supported for OAuth2",
            "Cognito Identity not configured"
    );

    private static final List<String> MOBILE_CLIENT_SIGNED_OUT_MESSAGES = Arrays.asList(
            "getTokens does not support retrieving tokens while signed-out"
    );

    private APAMobileClientSessionAdapter() { }

    static void fetchSignedOutSession(
            @NonNull AWSMobileClient awsMobileClient,
            @NonNull Consumer<AuthSession> onComplete) {

        // Try to get AWS Credentials - if the account doesn't support identity pools, Android AWSMobileClient throws an
        // exception with a "Cognito Identity not configured" message. Otherwise, if it returns an exception with the
        // message "Failed to get credentials from Cognito Identity" it could mean either Guest mode is supported
        // but the device is offline without cached credentials or Guest mode is not supported. Finally, if it returns
        // the credentials, that means Guest mode is supported so we then also retrieve the Identity ID.

        try {
            AWSCredentials result =  awsMobileClient.getAWSCredentials();

            fetchSignedOutSessionWithAWSCredentials(result, awsMobileClient, onComplete);

        }catch (Exception error) {

            if (error.getMessage().contains("Cognito Identity not configured")) {
                onComplete.accept(signedOutSessionWithoutIdentityPool());
            } else {
                onComplete.accept(signedOutSessionWithIdentityPool());
            }
        }


    }

    static void fetchSignedInSession(
            @NonNull AWSMobileClient awsMobileClient,
            @NonNull Consumer<AuthSession> onComplete) {

        try {

           Tokens result = awsMobileClient.getTokens();
            AuthSessionResult<String> userSubResult;

            userSubResult = getStringAuthSessionResult(result);

            AuthSessionResult<AWSCognitoUserPoolTokens> tokensResult =
                    AuthSessionResult.success(
                            new AWSCognitoUserPoolTokens(
                                    result.getAccessToken().getTokenString(),
                                    result.getIdToken().getTokenString(),
                                    result.getRefreshToken().getTokenString()
                            )
                    );

            fetchSignedInSessionWithUserPoolResults(
                    userSubResult,
                    tokensResult,
                    awsMobileClient,
                    onComplete
            );
        }catch (Exception error) {
            if (MOBILE_CLIENT_INVALID_ACCOUNT_MESSAGES.contains(error.getMessage())) {
                fetchIdentityPoolOnlySignedInSession(awsMobileClient, onComplete);
            } else if (MOBILE_CLIENT_SIGNED_OUT_MESSAGES.contains(error.getMessage())) {
                fetchSignedOutSession(awsMobileClient, onComplete);
            } else {
                fetchSignedInSessionWithUserPoolResults(
                        AuthSessionResult.failure(new AuthException.UnknownException(error)),
                        AuthSessionResult.failure(new AuthException.UnknownException(error)),
                        awsMobileClient,
                        onComplete
                );
            }

        }

    }

    @NotNull
    private static AuthSessionResult<String> getStringAuthSessionResult(Tokens result) {
        AuthSessionResult<String> userSubResult;
        try {
            userSubResult = AuthSessionResult.success(
                    CognitoJWTParser
                            .getPayload(result.getAccessToken().getTokenString())
                            .getString("sub")
            );
        } catch (JSONException error) {
            userSubResult = AuthSessionResult.failure(new AuthException.UnknownException(error));
        }
        return userSubResult;
    }

    private static void fetchIdentityPoolOnlySignedInSession(
            AWSMobileClient awsMobileClient,
            Consumer<AuthSession> onComplete) {
        AuthSessionResult<String> userSubResult =
                AuthSessionResult.failure(new AuthException.InvalidAccountTypeException());
        AuthSessionResult<AWSCognitoUserPoolTokens> tokensResult =
                AuthSessionResult.failure(new AuthException.InvalidAccountTypeException());

        fetchSignedInSessionWithUserPoolResults(
                userSubResult,
                tokensResult,
                awsMobileClient,
                onComplete
        );
    }

    private static void fetchSignedInSessionWithUserPoolResults(
            AuthSessionResult<String> userSubResult,
            AuthSessionResult<AWSCognitoUserPoolTokens> tokensResult,
            AWSMobileClient awsMobileClient,
            Consumer<AuthSession> onComplete) {

        try {
            AWSCredentials result = awsMobileClient.getAWSCredentials();
            if (result != null) {
                fetchSignedInSessionWithUserPoolAndAWSCredentialResults(
                        AuthSessionResult.success(result),
                        userSubResult,
                        tokensResult,
                        awsMobileClient,
                        onComplete
                );
            } else {
                AuthException error = new AuthException(
                        "Could not fetch AWS Cognito credentials, but there was no error reported back from " +
                                "AWSMobileClient.getAWSCredentials call.",
                        "This is a bug with the underlying AWSMobileClient");

                onComplete.accept(
                        new AWSCognitoAuthSession(
                                true,
                                AuthSessionResult.failure(error),
                                AuthSessionResult.failure(error),
                                userSubResult,
                                tokensResult
                        )
                );
            }

        }catch (Exception error) {

            AuthException wrappedError;

            if (MOBILE_CLIENT_INVALID_ACCOUNT_MESSAGES.contains(error.getMessage())) {
                wrappedError = new AuthException.InvalidAccountTypeException(error);
            } else {
                wrappedError = new AuthException.UnknownException(error);
            }

            onComplete.accept(
                    new AWSCognitoAuthSession(
                            true,
                            AuthSessionResult.failure(wrappedError),
                            AuthSessionResult.failure(wrappedError),
                            userSubResult,
                            tokensResult
                    )
            );
        }

    }

    private static void fetchSignedInSessionWithUserPoolAndAWSCredentialResults(
            AuthSessionResult<AWSCredentials> awsCredentialsResult,
            AuthSessionResult<String> userSubResult,
            AuthSessionResult<AWSCognitoUserPoolTokens> tokensResult,
            AWSMobileClient awsMobileClient, Consumer<AuthSession> onComplete
    ) {
        try {
            String identityId = awsMobileClient.getIdentityId();
            AuthSessionResult<String> identityIdResult;

            if (identityId != null) {
                identityIdResult = AuthSessionResult.success(identityId);
            } else {
                identityIdResult = AuthSessionResult.failure(new AuthException(
                        "AWSMobileClient returned awsCredentials but no identity id and no error",
                        "This should never happen and is a bug with AWSMobileClient."
                ));
            }

            onComplete.accept(
                    new AWSCognitoAuthSession(
                            true,
                            identityIdResult,
                            awsCredentialsResult,
                            userSubResult,
                            tokensResult
                    )
            );
        } catch (Exception identityIdError) {
            onComplete.accept(
                    new AWSCognitoAuthSession(
                            true,
                            AuthSessionResult.failure(new AuthException.UnknownException(identityIdError)),
                            awsCredentialsResult,
                            userSubResult,
                            tokensResult
                    )
            );
        }
    }

    private static void fetchSignedOutSessionWithAWSCredentials(
            AWSCredentials credentials,
            AWSMobileClient awsMobileClient,
            Consumer<AuthSession> onComplete) {

        try {
            String identityId = awsMobileClient.getIdentityId();

            onComplete.accept(
                    new AWSCognitoAuthSession(
                            false,
                            AuthSessionResult.success(identityId),
                            AuthSessionResult.success(credentials),
                            AuthSessionResult.failure(new AuthException.SignedOutException()),
                            AuthSessionResult.failure(new AuthException.SignedOutException())
                    )
            );
        } catch (Exception exception) {
            onComplete.accept(new AWSCognitoAuthSession(
                    false,
                    AuthSessionResult.failure(new AuthException(
                            "Retrieved guest credentials but failed to retrieve Identity ID",
                            exception,
                            "This should never happen. See the attached exception for more details.")),
                    AuthSessionResult.success(credentials),
                    AuthSessionResult.failure(new AuthException.SignedOutException()),
                    AuthSessionResult.failure(new AuthException.SignedOutException())
            ));
        }
    }

    private static AuthSession signedOutSessionWithoutIdentityPool() {
        return new AWSCognitoAuthSession(
                false,
                AuthSessionResult.failure(new AuthException.InvalidAccountTypeException()),
                AuthSessionResult.failure(new AuthException.InvalidAccountTypeException()),
                AuthSessionResult.failure(new AuthException.SignedOutException()),
                AuthSessionResult.failure(new AuthException.SignedOutException())
        );
    }

    private static AuthSession signedOutSessionWithIdentityPool() {
        return new AWSCognitoAuthSession(
                false,
                AuthSessionResult.failure(new AuthException.SignedOutException(
                        AuthException.GuestAccess.GUEST_ACCESS_POSSIBLE)),
                AuthSessionResult.failure(new AuthException.SignedOutException(
                        AuthException.GuestAccess.GUEST_ACCESS_POSSIBLE)),
                AuthSessionResult.failure(new AuthException.SignedOutException()),
                AuthSessionResult.failure(new AuthException.SignedOutException())
        );
    }
}
