require 'spec_helper'

RSpec.describe OmniAuth::Strategies::BnLauncher do

  it "has a version number" do
    expect(OmniAuth::Bn::Launcher::VERSION).not_to be nil
  end
end
