## Secure rails application using doorkeeper authentication using JWT (JSON Web Token)

Doorkeeper JWT adds JWT token support to the Doorkeeper OAuth library.

### Required dependencies: 
  * Ruby is installed (v 3.0.1)  
  * Rails is installed (v 6.1.4)  
  * MySQL is installed
  * Git is installed  
  * GitHub account is created

### Major steps are followed to setup:
  * Setup a new Rails app
  * Database configuration setup (using MySQL)
  * Initialize a local repository using git
  * .gitignore file created to add configuration.yml
  * configuration.yml file created to initialize environment variables  
  * Create a new remote repository using GitHub  
  * Change README.md and documentation added
  * Code Commited and Pushed to GitHub repository

## Create configuration.yml to setup required environment variables
	* Go to the config directory
	* Create a new file with name configuration.yml

### Required variables to define in configuration.yml
Here are the variables we need to define in this file:

````
DB_DEVELOPMENT_NAME: db_name_development

DB_DEVELOPMENT_USERNAME: test_user

DB_DEVELOPMENT_PASSWORD: test_password

DB_PRODUCTION_NAME: db_name_production

DB_PRODUCTION_USERNAME: test_pro

DB_PRODUCTION_PASSWORD: testing_password

DB_TEST_NAME: db_name_test

JWT_SECRET: jwt_secret_strong_xxxxxxxxxxxxxxxxxxxxxxx
````

### Create a model User with any of auth gem for login (Devise/bcrypt)
- We will create a User model to save user data.

- We will use bcrypt gem for password authentication.  

- Create a user via seed file so we can use same for login/logout etc 

## Settingup Doorkeeper (Server-side configuration)

```
# For making this application serve as an OAuth-Provider
# which can be used by OAuth Clients like a custom Webapp
gem 'doorkeeper'

# We are using JWT as the token generator for Doorkeeper hence this gem
gem 'doorkeeper-jwt'
```

Complete the gem installation, please go through with the gem documentation here is a [link](https://github.com/doorkeeper-gem/doorkeeper-jwt) for the same.

### Install doorkeeper and go through generated configurations files

Below files are referenced from directly gem documentation. We have to configure these as per our requirement. We have changed some of the part in doorkeeper.rb and routes.rb so please go through the changes as well. You can compair these via gem documentation or default generated files after installation.

#### /config/initializers/inflections.rb

```
# Reference: http://107.170.16.7/activesupport-inflector-and-you/
ActiveSupport::Inflector.inflections(:en) do |inflect|
  inflect.acronym 'OAuth'
end
```

#### /config/initializers/doorkeeper.rb 

```
Doorkeeper.configure do
  # Change the ORM that doorkeeper will use (needs plugins)
  orm :active_record

  # =======================STARTS: OVERRIDDEN CONFIG ===========================
  #
  # Note: Default values, wherever applicable, apply for options which are
  # not overridden here.
  
  # References:
  #  https://github.com/doorkeeper-gem/doorkeeper/wiki/Running-Doorkeeper-with-Devise
  #  https://dev.mikamai.com/2015/02/11/oauth2-on-rails/
  resource_owner_authenticator do |routes|
    if current_user
      current_user
    else
      # Refer the HERE document at the bottom on why this session variable
      # is being set.
      session[:user_return_to] = request.fullpath
      redirect_to(new_user_session_url)
    end
  end

  # References:
  #   https://github.com/doorkeeper-gem/doorkeeper/tree/v3.0.0.rc1#applications-list
  #   https://stackoverflow.com/questions/14273418/rails-3-how-to-restrict-access-to-the-web-interface-for-adding-oauth-authorized
  admin_authenticator do
    if current_user
      unless current_user.is_admin?
        redirect_to user_home_path, flash: { error: I18n.t('doorkeeper.applications_list.unauthorized_access') }
      end
    else
      redirect_to(new_user_session_url)
    end
  end

  # Access token expiration time (default 2 hours).
  # If you want to disable expiration, set this to nil.
  #
  access_token_expires_in 1.year

  access_token_generator '::Doorkeeper::JWT'

  # Refer https://github.com/doorkeeper-gem/doorkeeper/issues/383#issuecomment-324274231
  # for more details on why this is needed.
  reuse_access_token

  # =======================ENDS: OVERRIDDEN CONFIG =============================

  # This block will be called to check whether the resource owner is authenticated or not.
  # resource_owner_authenticator do
  #  fail "Please configure doorkeeper resource_owner_authenticator block located in #{__FILE__}"
  #  # Put your resource owner authentication logic here.
  #  # Example implementation:
  #  #   User.find_by_id(session[:user_id]) || redirect_to(new_user_session_url)
  # end

  # If you want to restrict access to the web interface for adding oauth authorized applications, you need to declare the block below.
  # admin_authenticator do
  #   # Put your admin authentication logic here.
  #   # Example implementation:
  #   Admin.find_by_id(session[:admin_id]) || redirect_to(new_admin_session_url)
  # end

  # Authorization Code expiration time (default 10 minutes).
  # authorization_code_expires_in 10.minutes

  # Access token expiration time (default 2 hours).
  # If you want to disable expiration, set this to nil.
  # access_token_expires_in 2.hours

  # Assign a custom TTL for implicit grants.
  # custom_access_token_expires_in do |oauth_client|
  #   oauth_client.application.additional_settings.implicit_oauth_expiration
  # end

  # Use a custom class for generating the access token.
  # https://github.com/doorkeeper-gem/doorkeeper#custom-access-token-generator
  # access_token_generator '::Doorkeeper::JWT'

  # The controller Doorkeeper::ApplicationController inherits from.
  # Defaults to ActionController::Base.
  # https://github.com/doorkeeper-gem/doorkeeper#custom-base-controller
  # base_controller 'ApplicationController'

  # Reuse access token for the same resource owner within an application (disabled by default)
  # Rationale: https://github.com/doorkeeper-gem/doorkeeper/issues/383
  # reuse_access_token

  # Issue access tokens with refresh token (disabled by default)
  # use_refresh_token

  # Provide support for an owner to be assigned to each registered application (disabled by default)
  # Optional parameter confirmation: true (default false) if you want to enforce ownership of
  # a registered application
  # Note: you must also run the rails g doorkeeper:application_owner generator to provide the necessary support
  # enable_application_owner confirmation: false

  # Define access token scopes for your provider
  # For more information go to
  # https://github.com/doorkeeper-gem/doorkeeper/wiki/Using-Scopes
  # default_scopes  :public
  # optional_scopes :write, :update

  # Change the way client credentials are retrieved from the request object.
  # By default it retrieves first from the `HTTP_AUTHORIZATION` header, then
  # falls back to the `:client_id` and `:client_secret` params from the `params` object.
  # Check out the wiki for more information on customization
  # client_credentials :from_basic, :from_params

  # Change the way access token is authenticated from the request object.
  # By default it retrieves first from the `HTTP_AUTHORIZATION` header, then
  # falls back to the `:access_token` or `:bearer_token` params from the `params` object.
  # Check out the wiki for more information on customization
  # access_token_methods :from_bearer_authorization, :from_access_token_param, :from_bearer_param

  # Change the native redirect uri for client apps
  # When clients register with the following redirect uri, they won't be redirected to any server and the authorization code will be displayed within the provider
  # The value can be any string. Use nil to disable this feature. When disabled, clients must provide a valid URL
  # (Similar behaviour: https://developers.google.com/accounts/docs/OAuth2InstalledApp#choosingredirecturi)
  #
  # native_redirect_uri 'urn:ietf:wg:oauth:2.0:oob'

  # Forces the usage of the HTTPS protocol in non-native redirect uris (enabled
  # by default in non-development environments). OAuth2 delegates security in
  # communication to the HTTPS protocol so it is wise to keep this enabled.
  #
  # force_ssl_in_redirect_uri !Rails.env.development?

  # Specify what grant flows are enabled in array of Strings. The valid
  # strings and the flows they enable are:
  #
  # "authorization_code" => Authorization Code Grant Flow
  # "implicit"           => Implicit Grant Flow
  # "password"           => Resource Owner Password Credentials Grant Flow
  # "client_credentials" => Client Credentials Grant Flow
  #
  # If not specified, Doorkeeper enables authorization_code and
  # client_credentials.
  #
  # implicit and password grant flows have risks that you should understand
  # before enabling:
  #   http://tools.ietf.org/html/rfc6819#section-4.4.2
  #   http://tools.ietf.org/html/rfc6819#section-4.4.3
  #
  # grant_flows %w(authorization_code client_credentials)

  # Under some circumstances you might want to have applications auto-approved,
  # so that the user skips the authorization step.
  # For example if dealing with a trusted application.
  # skip_authorization do |resource_owner, client|
  #   client.superapp? or resource_owner.admin?
  # end

  # WWW-Authenticate Realm (default "Doorkeeper").
  # realm "Doorkeeper"
end

Doorkeeper::JWT.configure do
  # Set the payload for the JWT token. This should contain unique information
  # about the user.
  # Defaults to a randomly generated token in a hash
  # { token: "RANDOM-TOKEN" }
  #
  # Additional references to prevent
  # ```
  #   422 error
  #
  #   ActiveRecord::RecordInvalid (Validation failed: Token has already been taken):
  # ```
  #
  #  https://stackoverflow.com/questions/31193369/repetitive-authorization-gives-error-422-with-doorkeeper-resource-owner-credent
  token_payload do |opts|
    user = User.find(opts[:resource_owner_id])

    {
      iss: Rails.application.class.parent.to_s.underscore,
      iat: Time.now.utc.to_i,
      jti: SecureRandom.uuid,

      user: {
        id: user.id,
        email: user.email
      }
    }
  end

  # Optionally set additional headers for the JWT. See https://tools.ietf.org/html/rfc7515#section-4.1
  # token_headers do |opts|
  #  {
  #    kid: opts[:application][:uid]
  #  }
  # end

  # Use the application secret specified in the Access Grant token
  # Defaults to false
  # If you specify `use_application_secret true`, both secret_key and secret_key_path will be ignored
  # use_application_secret false

  # Set the encryption secret. This would be shared with any other applications
  # that should be able to read the payload of the token.
  # Defaults to "secret"
  #
  secret_key ENV["JWT_ENCRYPTION_SECRET"]

  # If you want to use RS* encoding specify the path to the RSA key
  # to use for signing.
  # If you specify a secret_key_path it will be used instead of secret_key
  # secret_key_path "path/to/file.pem"

  # Specify encryption type. Supports any algorithim in
  # https://github.com/progrium/ruby-jwt
  # defaults to nil
  encryption_method :hs256
end

=begin

 Why this specific session variable? Because Devise looks for this name
 Refer `after_sign_in_path_for(resource_or_scope)` method
 implementation and documentation at

  https://github.com/plataformatec/devise/blob/v4.2.0/lib/devise/controllers/helpers.rb#L213

 and you should get it why.

  https://github.com/plataformatec/devise/blob/v4.2.0/lib/devise/controllers/store_location.rb#L17
  https://github.com/plataformatec/devise/blob/v4.2.0/lib/devise/controllers/store_location.rb#L54

 And `after_sign_in_path_for` method should come into picture when Client-app
 sends an authorization request to this Provider-app and the user is not
 found to be logged-in on the Provider-app. So Devise should throw
 the user to the Sign-in page and after successful sign-in user should
 be redirected to the Client-app. So we are storing the Client-app's
 path here in a session key supported by Devise in out-of-the-box fashion
 for handling redirects to original page after signing-in.

 So just setting this session variable Devise should handle the redirect
 to Client-app AFTER SUCCESSFUL SIGN-IN without any additional changes
 in it's SessionsController implementation.

 References:
  https://dev.mikamai.com/2015/02/11/oauth2-on-rails/
  https://stackoverflow.com/a/21632889/936494

 Note that if this session variable is NOT set then what would happen is
 that when user from Client-app sends authorization request and user
 is not NOT found logged-in by Devise on this Provider-app
 the Provider-app display's Sign Page but after successful login
 Provider-app doesn't redirect the logged-in user to Client-app.

 However that's not the case when user is found logged-in on this Provider-app
 In that case Provider-app displays the Authorize/Deny page facilitated
 by Doorkeeper. Clicking either on Authorize or Deny button the redirect
 happens!


 THIS SHOULD WORK ASSUMING YOU HAVE NOT ALREADY OVERRIDDEN

   after_sign_in_path_for(resource)`

 in your ApplicationController like following

   def after_sign_in_path_for(resource)
     user_home_path
   end

 If that is the case then setting this session variable should have NO EFFECT.
 And to fix that you will need to do this

    def after_sign_in_path_for(resource)
      stored_location_for(resource) || user_home_path
    end

=end


```

#### /config/routes.rb

```
Rails.application.routes.draw do

  # This should be automatically added by Doorkeeper when installing it 
  # using the insructions at https://github.com/doorkeeper-gem/doorkeeper#installation
  use_doorkeeper 
  
  # OAuth protected routes which can be requested by Client-app  
  namespace :oauth_protected, path: 'oauthorized' do
    defaults format: :json do
      get :me, to: 'users#me', as: :me
    end
  end
```

#### /app/controllers/oauth_protected/base_controller.rb

```
module OAuthProtected
  class BaseController < ::ActionController::Base

    # Reference: https://github.com/doorkeeper-gem/doorkeeper#protecting-resources-with-oauth-aka-your-api-endpoint
    before_action :doorkeeper_authorize! # Require access token for all actions

    private

    # Find the user that owns the access token
    #
    # Reference: https://github.com/doorkeeper-gem/doorkeeper/tree/v3.0.0.rc1#authenticated-resource-owner
    def current_resource_owner
      User.find(doorkeeper_token.resource_owner_id) if doorkeeper_token
    end

  end
end
```

#### /app/controllers/oauth_protected/users_controller.rb

```
module OAuthProtected
  class UsersController < BaseController

    # GET /oauthorized/me(.:format)
    def me
      user_json = current_resource_owner.as_json

      render json: user_json, status: 200
    end

  end
end
```

* Doorkeeper OAuth applications list can be accessed using the route `/oauth/applications`. On localhost it should be 
http://localhost:3000/oauth/applications

* Redirect URI example for a Rails Client-app running on port 5000 and using Devise's Omniauthable module  

   http://localhost:5000/users/auth/doorkeeper/callback


## Doorkeeper Auth section endpoints 

In this demo user is created via seed file. We are directly going to login user with his login details.

#### Login (Issue access token)
- You need to call POST /oauth/token with body mentioned below. We need to add grant_type and client id and secrets in the body with email and password. 

- The way of passing client_id and client_secret as mentioned below body isn't recommended by the RFC however this will work. We have to pass these through encrypted headers. I will explain the secure way at bottom section.

Request body:
````
{
    "grant_type": "password",
    "email": "jai@example.com",
    "password": "0000000",
    "client_id": "uZmSxDz1zznGyldoeo3zzxxxxxxxxxxxxxxxxxx",
    "client_secret": "absxyMmgaQWD1xxxxxxxxxxxxxxxxxx"
}
````

#### Use Refresh Token to issue a new access token
- You need to call POST /oauth/token with body mentioned below. The only change is grant_type value.

Request body:
``````
{
    "grant_type": "refresh_token",
    "refresh_token": "KL75Xrdxxxxxxxxxxxxxxxxxxxxx",
    "client_id": "uZmSxDz1zznGyldoeo3zzxxxxxxxxxxxxxxxxxx",
    "client_secret": "absxyMmgaQWD1xxxxxxxxxxxxxxxxxx"
}

``````

#### Logout (Revoke an access token)
- You need to call POST /token/revoke 

- Key "token" value of access_token you wanna to revoke in body

- Include authorization headers (**HTTP-Authrozation: Basic Base64(client_id:client_secret)**) to inform the server that this request is authorized to perform an action. 

- Check below section to secure this data transmission


#### Send client_id and client_secret in a secure way instead of body
- Alternatively you could send client_id and client_secret via body params, but this method isn't recommended by the RFC. So here is another way you can pass your client data.

- Don't forget that if the token you wanna to revoke was issued to some specific client - only this client could revoke the token (it's credentials must be used to authorize the request).

Here is an Example:

Suppose your client_id is xxxxxxxx1234 and client_secret is zzzzzzzz0987 so you can generate base64 basic token via:

````
data = "xxxxxxxx1234:zzzzzzzz0987"
basic_auth = Base64.strict_encode64(data) 
# returns: dVptU3hEejF6em5HeVZHR18ybWg2amNub1pZSWNHcW5xQy1DSm02SEtpVTphYnN4eU1tZ2FRV0QxV0dUTjExd29jYlBRWGJqTkFWYlRfSl9fYjE5TnZr
````
##### Request:

`POST /token/revoke`

Use (above generated) token in request headers:

````
{
  "Authorization":  "Basic dVptU3hEejF6em5HeVZHR18ybWg2amNub1pZSWNHcW5xQy1DSm02SEtpVTphYnN4eU1tZ2FRV0QxV0dUTjExd29jYlBRWGJqTkFWYlRfSl9fYjE5TnZr"
}
````
Body: 

````
{
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJNeSBBcHAiLCJpYXQiOjE2NjQ5NjY3MTcsImp0aSI6IjQyMjhkNzE4LWMzYTQtNGI2My1hYjEwLTRhYWQxM2Q2NzFkZiIsInVzZXIiOnsiaWQiOjEsImVtYWlsIjoiamFpQHRlY29yYi5jbyJ9fQ.NqqCEoYC4E3D5xo3_VHQm_eW292jVQGFWM53MCozyk9XI8rErYE6dNxw0Ksai853X6hSLw9ujuapD2rX4XXaOQ"
}
````