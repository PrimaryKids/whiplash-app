require "spec_helper"

describe Whiplash::App::Connections do
  let(:first_request) { OpenStruct.new(success?: true, body: (1..50).to_a) }
  let(:second_request) { OpenStruct.new(success?: true, body: (1..10).to_a) }
  let(:whiplash_app) { Whiplash::App.new }

  before do
    allow_any_instance_of(Whiplash::App).to receive(:token).and_return(double(token: 'access token'))
    allow_any_instance_of(Faraday::Connection).to receive(:send).with(:get, "core_url", {:per_page=>50}, {"Accept-Version"=>"v2"}).and_return(first_request)
    allow_any_instance_of(Faraday::Connection).to receive(:send).with(:get, "core_url", {:page => 2, :per_page=>50}, {"Accept-Version" => "v2"}).and_return(second_request)
  end

  context 'GET calls' do
    describe '#multi_page_get!' do
      it 'returns an array' do
          expect(whiplash_app.multi_page_get!('core_url', {}, nil).class).to equal Array
      end

      it 'returns the correct numbers of results' do
          expect(whiplash_app.multi_page_get!('core_url', {}, nil).size).to equal 60
      end
    end
  end
end
