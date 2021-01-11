import com.amazonaws.mobile.client.AWSMobileClient
import com.amazonaws.mobile.client.Callback
import com.amazonaws.mobile.client.UserState
import com.amazonaws.mobile.client.results.SignInResult
import com.amazonaws.mobile.client.results.SignInState
import com.amazonaws.mobile.client.results.Tokens
import com.amazonaws.mobile.client.results.UserCodeDeliveryDetails
import com.amazonaws.mobileconnectors.cognitoidentityprovider.util.CognitoJWTParser
import com.amplifyframework.auth.AuthCodeDeliveryDetails
import com.amplifyframework.auth.AuthException
import com.amplifyframework.auth.AuthException.SessionExpiredException
import com.amplifyframework.auth.AuthSession
import com.amplifyframework.auth.cognito.AWSCognitoAuthPlugin
import com.amplifyframework.auth.cognito.AWSCognitoAuthSession
import com.amplifyframework.auth.cognito.options.AWSCognitoAuthSignInOptions
import com.amplifyframework.auth.cognito.util.CognitoAuthExceptionConverter
import com.amplifyframework.auth.cognito.util.SignInStateConverter
import com.amplifyframework.auth.options.AuthSignInOptions
import com.amplifyframework.auth.result.AuthSessionResult
import com.amplifyframework.auth.result.AuthSignInResult
import com.amplifyframework.auth.result.step.AuthNextSignInStep
import com.amplifyframework.core.Action
import com.amplifyframework.core.Consumer
import org.json.JSONException
import timber.log.Timber
import kotlin.jvm.Throws

/**
 * 增加一个同步的token获取
 * Created by Arthur on 2020/10/14.
 */
object APAASessionHelper {
    private const val COGNITO_USER_ID_ATTRIBUTE = "sub"


    fun getAuthToken():String?  {

        var token: String? = null

        fetchAuthSession(Consumer<AuthSession?> { session ->
            val result = session as AWSCognitoAuthSession
            Timber.e("fetchSession in: ${result}")
            if (result.isSignedIn) {

                val userPoolTokens = session.userPoolTokens

                if(userPoolTokens.type == AuthSessionResult.Type.SUCCESS) {

                    token = userPoolTokens.value?.idToken

                }

            }
        }, Consumer<AuthException?> {
            Timber.e("fetchSession in: $it")

            token = null

        })


        return token
    }


   private fun signIn(
        username: String?,
        password: String?,
        onSuccess: Consumer<AuthSignInResult?>,
        onException: Consumer<AuthException?>
    ) {
        signIn(
            username,
            password,
            AWSCognitoAuthSignInOptions.builder().build(),
            onSuccess,
            onException
        )
    }

    fun signIn(
        username: String?,
        password: String?,
        options: AuthSignInOptions?,
        onSuccess: Consumer<AuthSignInResult?>,
        onException: Consumer<AuthException?>
    ) {
        var metadata: Map<String?, String?>? = null
        if (options != null && options is AWSCognitoAuthSignInOptions) {
            metadata = options.metadata
        }
        val awsMobileClient: AWSMobileClient = AWSMobileClient.getInstance()

        try {
            val result =  awsMobileClient.signIn(username,password,metadata)

            try {
                val newResult: AuthSignInResult = convertSignInResult(result)
                fetchAndSetUserId(Action {
                    onSuccess.accept(
                        newResult
                    )
                })
            } catch (exception: AuthException) {
                onException.accept(exception)
            }
        }catch (e: Exception) {

            onException.accept(
                CognitoAuthExceptionConverter.lookup(e, "Sign in failed")
            )
        }

    }

    @Throws(AuthException::class)
    private fun convertSignInResult(result: SignInResult): AuthSignInResult {
        return AuthSignInResult(
            SignInState.DONE == result.signInState,
            AuthNextSignInStep(
                SignInStateConverter.getAuthSignInStep(result.signInState),
                if (result.parameters == null) emptyMap() else result.parameters,
                convertCodeDeliveryDetails(result.codeDetails)
            )
        )
    }

    private fun convertCodeDeliveryDetails(details: UserCodeDeliveryDetails?): AuthCodeDeliveryDetails? {
        return if (details != null) AuthCodeDeliveryDetails(
            details.destination,
            AuthCodeDeliveryDetails.DeliveryMedium.fromString(details.deliveryMedium),
            details.attributeName
        ) else null
    }

    private fun fetchAndSetUserId(onComplete: Action) {
        val awsMobileClient: AWSMobileClient = AWSMobileClient.getInstance()

        awsMobileClient.getTokens(object :
            Callback<Tokens> {
            override fun onResult(result: Tokens) {
                onComplete.call()
            }

            override fun onError(error: java.lang.Exception) {
                onComplete.call()
            }
        })
    }

    private fun getUserIdFromToken(token: String): String? {
        return try {
            CognitoJWTParser
                .getPayload(token)
                .getString(COGNITO_USER_ID_ATTRIBUTE)
        } catch (error: JSONException) {
            null
        }
    }

   private fun fetchAuthSession(
        onSuccess: Consumer<AuthSession?>,
        onException: Consumer<AuthException?>
    ) {
        val awsMobileClient: AWSMobileClient = AWSMobileClient.getInstance()

        try {
            try {
                val result =  awsMobileClient.currentUserState()

                when (result.userState) {
                    UserState.SIGNED_OUT, UserState.GUEST -> {

                        APAMobileClientSessionAdapter.fetchSignedOutSession(
                            awsMobileClient,
                            onSuccess
                        )
                    }
                    UserState.SIGNED_OUT_FEDERATED_TOKENS_INVALID, UserState.SIGNED_OUT_USER_POOLS_TOKENS_INVALID -> onSuccess.accept(
                        expiredSession()
                    )
                    else -> APAMobileClientSessionAdapter.fetchSignedInSession(
                        awsMobileClient,
                        onSuccess
                    )
                }
            }catch (exception: java.lang.Exception) {

                onException.accept(
                    AuthException(
                        "An error occurred while attempting to retrieve your user details",
                        exception,
                        "See attached exception for more details"
                    )
                )
            }

        } catch (exception: Throwable) {
            onException.accept(
                AuthException(
                    "An error occurred fetching authorization details for the current user",
                    exception,
                    "See attached exception for more details"
                )
            )
        }
    }

    private fun expiredSession(): AuthSession {
        return AWSCognitoAuthSession(
            true,
            AuthSessionResult.failure(SessionExpiredException()),
            AuthSessionResult.failure(SessionExpiredException()),
            AuthSessionResult.failure(SessionExpiredException()),
            AuthSessionResult.failure(SessionExpiredException())
        )
    }
}
