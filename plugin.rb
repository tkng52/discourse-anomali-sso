# name: discourse-anomali-sso
# about: Anomali SSO Plugin
# version: 0.1
# authors: TK

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :threatstream_enabled
enabled_site_setting :reports_enabled
enabled_site_setting :anomali_enabled

after_initialize do
  load File.expand_path("../controllers/anomali_controller.rb", __FILE__)

  Discourse::Application.routes.prepend do
    get 'anomali/sso_threatstream' => 'anomali#sso_threatstream'
    get 'anomali/sso_reports' => 'anomali#sso_reports'
    get 'anomali/sso_login' => 'anomali#sso_login'
  end

end

class ::OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"
  info do
    {
      id: access_token['id']
    }
  end
end


############### Theatstream ###############

class OAuth2BasicAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: 'threatstream_basic',
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                      }
  end

  def after_authenticate(auth)
  end

end

auth_provider title_setting: "threatstream_button_title",
              enabled_setting: "threatstream_enabled",
              authenticator: OAuth2BasicAuthenticator.new('threatstream_basic'),
              message: "OAuth2",
              custom_url: "http://ubuntuserver14041w-tkdiscourse-dywim4vu.srv.ravcloud.com/anomali/sso_threatstream?return_path=%2F",
              # custom_url: "https://devdiscourse01.threatstream.com/anomali/sso_threatstream?return_path=%2F",
              # custom_url: "http://localhost:4000/anomali/sso_threatstream?return_path=%2F",
              full_screen_login: true

register_css <<CSS
  button.btn-social.threatstream_basic {
    background-color: #57C4BF;
  }
CSS



 ############### Reports ###############

class ReportsBasicAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: 'reports_basic',
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                      }
  end

  def after_authenticate(auth)
  end

end

auth_provider title_setting: "reports_button_title",
              enabled_setting: "reports_enabled",
              authenticator: OAuth2BasicAuthenticator.new('reports_basic'),
              message: "OAuth2",
              custom_url: "http://ubuntuserver14041w-tkdiscourse-dywim4vu.srv.ravcloud.com/anomali/sso_reports?return_path=%2F",
              # custom_url: "https://devdiscourse01.threatstream.com/anomali/sso_reports?return_path=%2F",
              # custom_url: "http://localhost:4000/anomali/sso_reports?return_path=%2F",
              full_screen_login: true

register_css <<CSS
  button.btn-social.reports_basic {
    background-color: #F79420;
  }
CSS


############### Another Anomali Product ###############

class AnomaliBasicAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: 'anomali_basic',
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                      }
  end

  def after_authenticate(auth)
  end

end

auth_provider title_setting: "anomali_button_title",
              enabled_setting: "anomali_enabled",
              authenticator: OAuth2BasicAuthenticator.new('anomali_basic'),
              message: "OAuth2",
              custom_url: "http://ubuntuserver14041w-tkdiscourse-dywim4vu.srv.ravcloud.com/anomali/sso_anomali?return_path=%2F",
              # custom_url: "https://devdiscourse01.threatstream.com/anomali/sso_anomali?return_path=%2F",
              # custom_url: "http://localhost:4000/anomali/sso_anomali?return_path=%2F",
              full_screen_login: true

register_css <<CSS
  button.btn-social.anomali_basic {
    background-color: #D4DF43;
  }
CSS
