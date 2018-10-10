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
        redirect login_page_url
      end

      def callback_phase
        slug = request.params['slug']
        @auth_token = request.params['p_aa_token']
        @account = Account.find_by(slug: slug)
        @app_event = @account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

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
        user_info = @auth_token.present? ? auth_service.authenticate_and_get_user_data : user_info_from_params
        return {} unless user_info
        {
          uid: user_info[:uid],
          first_name: user_info[:first_name],
          last_name: user_info[:last_name],
          email: user_info[:email],
          username: user_info[:username],
          access_codes: user_info[:access_codes]
        }
      end

      private

      def user_info_from_params
        {
          uid: request.params['uid'],
          first_name: request.params['first_name'],
          last_name: request.params['last_name'],
          email: request.params['email'],
          username: request.params['username'],
          access_codes: request.params['access_codes']
        }
      end

      def auth_service
        @auth_service ||= Integrations::AssociationAnywhere::Login.new(@account, { app_event_id: @app_event, auth_token: @auth_token })
      end

      def restore_session?
        request.params['restore_session'].present?
      end

      def login_page_url
        options.client_options.login_page_url
      end
    end
  end
end
