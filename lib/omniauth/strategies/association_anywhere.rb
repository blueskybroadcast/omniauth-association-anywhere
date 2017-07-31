require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class AssociationAnywhere < OmniAuth::Strategies::OAuth2
      option :name, 'association_anywhere'

      option :app_options, { app_event_id: nil }

      option :client_options, { login_page_url: 'MUST BE PROVIDED' }

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//, '')
        redirect login_page_url + '?redirectURL=' + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.redirect_url'] = request.params['redirect_url'].presence if restore_session?
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid, restore_session: restore_session?)
        hash.info = info
        hash
      end

      def raw_user_info
        {
          uid: request.params['uid'],
          first_name: request.params['first_name'],
          last_name: request.params['last_name'],
          email: request.params['email'],
          username: request.params['username'],
          access_codes: request.params['access_codes']
        }
      end

      private

      def restore_session?
        request.params['restore_session'].present?
      end

      def login_page_url
        options.client_options.login_page_url
      end
    end
  end
end
