# frozen_string_literal: true

class Api::V1::AccountsController < Api::BaseController
  before_action -> { authorize_if_got_token! :read, :'read:accounts' }, except: [:create, :set_password, :follow, :unfollow, :remove_from_followers, :block, :unblock, :mute, :unmute]
  before_action -> { doorkeeper_authorize! :follow, :'write:follows' }, only: [:follow, :unfollow, :remove_from_followers]
  before_action -> { doorkeeper_authorize! :follow, :'write:mutes' }, only: [:mute, :unmute]
  before_action -> { doorkeeper_authorize! :follow, :'write:blocks' }, only: [:block, :unblock]
  before_action -> { doorkeeper_authorize! :write, :'write:accounts' }, only: [:create, :set_password]

  before_action :require_user!, except: [:show, :create]
  before_action :set_account, except: [:create]
  # enable API signup
  # TODO app_id validation
  # before_action :check_enabled_registrations, only: [:create]

  skip_before_action :require_authenticated_user!, only: [:create, :set_password]

  # disable API rate_limit to avoid app congestion
  # override_rate_limit_headers :follow, family: :follows

  def show
    render json: @account, serializer: REST::AccountSerializer
  end

  def create
    token    = AppSignUpService.new.call(doorkeeper_token.application, request.remote_ip, account_params)
    response = Doorkeeper::OAuth::TokenResponse.new(token)

    headers.merge!(response.headers)

    self.response_body = Oj.dump(response.body)
    self.status        = response.status
  rescue ActiveRecord::RecordInvalid => e
    render json: ValidationErrorFormatter.new(e, :'account.username' => :username, :'invite_request.text' => :reason).as_json, status: :unprocessable_entity
  end

  def set_password
   @user = @account.user
   @user.password = account_params[:password]
   @user.save(:validate => true)

   render json: @account, serializer: REST::AccountSerializer
  end

  def confirm_account
   @account.user.update!(confirmed_at: Time.now.utc)
   @account.update!(discoverable: true)

   render json: @account, serializer: REST::AccountSerializer
  end

  def follow
    follow  = FollowService.new.call(current_user.account, @account, reblogs: params.key?(:reblogs) ? truthy_param?(:reblogs) : nil, notify: params.key?(:notify) ? truthy_param?(:notify) : nil, with_rate_limit: true)
    options = @account.locked? || current_user.account.silenced? ? {} : { following_map: { @account.id => { reblogs: follow.show_reblogs?, notify: follow.notify? } }, requested_map: { @account.id => false } }

    render json: @account, serializer: REST::RelationshipSerializer, relationships: relationships(**options)
  end

  def block
    BlockService.new.call(current_user.account, @account)
    render json: @account, serializer: REST::RelationshipSerializer, relationships: relationships
  end

  def mute
    MuteService.new.call(current_user.account, @account, notifications: truthy_param?(:notifications), duration: (params[:duration]&.to_i || 0))
    render json: @account, serializer: REST::RelationshipSerializer, relationships: relationships
  end

  def unfollow
    UnfollowService.new.call(current_user.account, @account)
    render json: @account, serializer: REST::RelationshipSerializer, relationships: relationships
  end

  def remove_from_followers
    RemoveFromFollowersService.new.call(current_user.account, @account)
    render json: @account, serializer: REST::RelationshipSerializer, relationships: relationships
  end

  def unblock
    UnblockService.new.call(current_user.account, @account)
    render json: @account, serializer: REST::RelationshipSerializer, relationships: relationships
  end

  def unmute
    UnmuteService.new.call(current_user.account, @account)
    render json: @account, serializer: REST::RelationshipSerializer, relationships: relationships
  end

  private

  def set_account
    @account = Account.find(params[:id])
  end

  def relationships(**options)
    AccountRelationshipsPresenter.new([@account.id], current_user.account_id, **options)
  end

  def account_params
    params.permit(:username, :email, :password, :agreement, :locale, :reason)
  end

  def check_enabled_registrations
    forbidden if single_user_mode? || omniauth_only? || !allowed_registrations?
  end

  def allowed_registrations?
    Setting.registrations_mode != 'none'
  end

  def omniauth_only?
    ENV['OMNIAUTH_ONLY'] == 'true'
  end
end
