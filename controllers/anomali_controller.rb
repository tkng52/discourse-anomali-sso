class ::AnomaliController < ::ApplicationController

  skip_before_filter :redirect_to_login_if_required
  skip_before_filter :preload_json, :check_xhr, only: ['sso_threatstream', 'sso_reports', 'sso_anomali','sso_login','sso_login2']


  def sso_threatstream
    destination_url = cookies[:destination_url] || session[:destination_url]
    return_path = params[:return_path] || path('/')

    if destination_url && return_path == path('/')
      uri = URI::parse(destination_url)
      return_path = "#{uri.path}#{uri.query ? "?" << uri.query : ""}"
    end

    session.delete(:destination_url)
    cookies.delete(:destination_url)

    sso = DiscourseSingleSignOn.generate_sso(return_path)
    if SiteSetting.verbose_sso_logging
      Rails.logger.warn("Verbose SSO log: Started SSO process\n\n#{sso.diagnostics}")
    end

    base = SiteSetting.threatstream_sso_url
    redirect_to "#{base}#{base.include?('?') ? '&' : '?'}#{sso.payload}"
    # redirect_to sso.to_url
  end

  def sso_reports
    destination_url = cookies[:destination_url] || session[:destination_url]
    return_path = params[:return_path] || path('/')

    if destination_url && return_path == path('/')
      uri = URI::parse(destination_url)
      return_path = "#{uri.path}#{uri.query ? "?" << uri.query : ""}"
    end

    session.delete(:destination_url)
    cookies.delete(:destination_url)

    sso = DiscourseSingleSignOn.generate_sso(return_path)
    if SiteSetting.verbose_sso_logging
      Rails.logger.warn("Verbose SSO log: Started SSO process\n\n#{sso.diagnostics}")
    end

    base = SiteSetting.reports_sso_url
    redirect_to "#{base}#{base.include?('?') ? '&' : '?'}#{sso.payload}"
    # redirect_to sso.to_url
  end

  def sso_anomali
    destination_url = cookies[:destination_url] || session[:destination_url]
    return_path = params[:return_path] || path('/')

    if destination_url && return_path == path('/')
      uri = URI::parse(destination_url)
      return_path = "#{uri.path}#{uri.query ? "?" << uri.query : ""}"
    end

    session.delete(:destination_url)
    cookies.delete(:destination_url)

    sso = AnomaliSingleSignOn.generate_sso(return_path)
    if SiteSetting.verbose_sso_logging
      Rails.logger.warn("Verbose SSO log: Started SSO process\n\n#{sso.diagnostics}")
    end

    base = SiteSetting.anomali_sso_url
    redirect_to "#{base}#{base.include?('?') ? '&' : '?'}#{sso.payload}"
    # redirect_to sso.to_url
  end

  def sso_login
    # unless SiteSetting.enable_sso
    #   return render(nothing: true, status: 404)
    # end

    sso = DiscourseSingleSignOn.parse(request.query_string)
    if !sso.nonce_valid?
      if SiteSetting.verbose_sso_logging
        Rails.logger.warn("Verbose SSO log: Nonce has already expired\n\n#{sso.diagnostics}")
      end
      return render(text: I18n.t("sso.timeout_expired"), status: 419)
    end

    if ScreenedIpAddress.should_block?(request.remote_ip)
      if SiteSetting.verbose_sso_logging
        Rails.logger.warn("Verbose SSO log: IP address is blocked #{request.remote_ip}\n\n#{sso.diagnostics}")
      end
      return render(text: I18n.t("sso.unknown_error"), status: 500)
    end

    return_path = sso.return_path
    sso.expire_nonce!

    begin
      if user = sso.lookup_or_create_user(request.remote_ip)

        if SiteSetting.must_approve_users? && !user.approved?
          if SiteSetting.sso_not_approved_url.present?
            redirect_to SiteSetting.sso_not_approved_url
          else
            render text: I18n.t("sso.account_not_approved"), status: 403
          end
          return
        elsif !user.active?
          activation = UserActivator.new(user, request, session, cookies)
          activation.finish
          session["user_created_message"] = activation.message
          redirect_to users_account_created_path and return
        else
          if SiteSetting.verbose_sso_logging
            Rails.logger.warn("Verbose SSO log: User was logged on #{user.username}\n\n#{sso.diagnostics}")
          end
          log_on_user user
        end

        # If it's not a relative URL check the host
        if return_path !~ /^\/[^\/]/
          begin
            uri = URI(return_path)
            return_path = path("/") unless uri.host == Discourse.current_hostname
          rescue
            return_path = path("/")
          end
        end

        redirect_to return_path
      else
        render text: I18n.t("sso.not_found"), status: 500
      end
    rescue ActiveRecord::RecordInvalid => e
      if SiteSetting.verbose_sso_logging
        Rails.logger.warn(<<-EOF)
          Verbose SSO log: Record was invalid: #{e.record.class.name} #{e.record.id}\n
          #{e.record.errors.to_h}\n
          \n
          #{sso.diagnostics}
        EOF
      end
      render text: I18n.t("sso.unknown_error"), status: 500
    rescue => e
      message = "Failed to create or lookup user: #{e}."
      message << "\n\n" << "-" * 100 << "\n\n"
      message << sso.diagnostics
      message << "\n\n" << "-" * 100 << "\n\n"
      message << e.backtrace.join("\n")

      Rails.logger.error(message)

      render text: I18n.t("sso.unknown_error"), status: 500
    end
  end

  def sso_login2
    # unless SiteSetting.enable_sso
    #   return render(nothing: true, status: 404)
    # end

    sso = AnomaliSingleSignOn.parse(request.query_string)
    if !sso.nonce_valid?
      if SiteSetting.verbose_sso_logging
        Rails.logger.warn("Verbose SSO log: Nonce has already expired\n\n#{sso.diagnostics}")
      end
      return render(text: I18n.t("sso.timeout_expired"), status: 419)
    end

    if ScreenedIpAddress.should_block?(request.remote_ip)
      if SiteSetting.verbose_sso_logging
        Rails.logger.warn("Verbose SSO log: IP address is blocked #{request.remote_ip}\n\n#{sso.diagnostics}")
      end
      return render(text: I18n.t("sso.unknown_error"), status: 500)
    end

    return_path = sso.return_path
    sso.expire_nonce!

    begin
      if user = sso.lookup_or_create_user(request.remote_ip)

        if SiteSetting.must_approve_users? && !user.approved?
          if SiteSetting.sso_not_approved_url.present?
            redirect_to SiteSetting.sso_not_approved_url
          else
            render text: I18n.t("sso.account_not_approved"), status: 403
          end
          return
        elsif !user.active?
          activation = UserActivator.new(user, request, session, cookies)
          activation.finish
          session["user_created_message"] = activation.message
          redirect_to users_account_created_path and return
        else
          if SiteSetting.verbose_sso_logging
            Rails.logger.warn("Verbose SSO log: User was logged on #{user.username}\n\n#{sso.diagnostics}")
          end
          log_on_user user
        end

        # If it's not a relative URL check the host
        if return_path !~ /^\/[^\/]/
          begin
            uri = URI(return_path)
            return_path = path("/") unless uri.host == Discourse.current_hostname
          rescue
            return_path = path("/")
          end
        end

        redirect_to return_path
      else
        render text: I18n.t("sso.not_found"), status: 500
      end
    rescue ActiveRecord::RecordInvalid => e
      if SiteSetting.verbose_sso_logging
        Rails.logger.warn(<<-EOF)
          Verbose SSO log: Record was invalid: #{e.record.class.name} #{e.record.id}\n
          #{e.record.errors.to_h}\n
          \n
          #{sso.diagnostics}
        EOF
      end
      render text: I18n.t("sso.unknown_error"), status: 500
    rescue => e
      message = "Failed to create or lookup user: #{e}."
      message << "\n\n" << "-" * 100 << "\n\n"
      message << sso.diagnostics
      message << "\n\n" << "-" * 100 << "\n\n"
      message << e.backtrace.join("\n")

      Rails.logger.error(message)

      render text: I18n.t("sso.unknown_error"), status: 500
    end
  end


  def lookup_or_create_user(sso, ip_address=nil)
    sso_record = SingleSignOnRecord.find_by(external_id: external_id)

    if sso_record && (user = sso_record.user)
      sso_record.last_payload = sso.unsigned_payload
    else
      user = sso.match_email_or_create_user(ip_address)
      sso_record = user.single_sign_on_record
    end

    # ensure it's not staged anymore
    user.staged = false

    # if the user isn't new or it's attached to the SSO record we might be overriding username or email
    unless user.new_record?
      sso.change_external_attributes_and_override(sso_record, user)
    end

    if sso_record && (user = sso_record.user) && !user.active && !require_activation
      user.active = true
      user.save!
      user.enqueue_welcome_message('welcome_user') unless suppress_welcome_message
    end

    custom_fields.each do |k,v|
      user.custom_fields[k] = v
    end

    user.ip_address = ip_address

    user.admin = admin unless admin.nil?
    user.moderator = moderator unless moderator.nil?

    # optionally save the user and sso_record if they have changed
    user.user_avatar.save! if user.user_avatar
    user.save!

    if bio && (user.user_profile.bio_raw.blank? || SiteSetting.sso_overrides_bio)
      user.user_profile.bio_raw = bio
      user.user_profile.save!
    end

    unless admin.nil? && moderator.nil?
      Group.refresh_automatic_groups!(:admins, :moderators, :staff)
    end

    sso_record.save!

    sso_record && sso_record.user
  end


end
