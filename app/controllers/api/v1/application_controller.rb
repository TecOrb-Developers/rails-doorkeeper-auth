class Api::V1::ApplicationController < ActionController::Base
	skip_before_action :verify_authenticity_token
	include ResponseJson
	before_action :doorkeeper_authorize!

	def doorkeeper_unauthorized_render_options(error: nil)
		{ json: { errors: error.description } }
	end
end
