require 'securerandom'
require 'ostruct'

describe Match do
  describe Match::Storage::GitLab::Client do
    subject {
      described_class.new(
        api_v4_url: 'https://gitlab.example.com/api/v4',
        project_id: 'sample/project',
        private_token: 'abc123'
      )
    }

    # --- existing specs retained ---
    describe '#base_url' do
      it 'returns the expected base_url for the given configuration' do
        expect(subject.base_url).to eq('https://gitlab.example.com/api/v4/projects/sample%2Fproject/secure_files')
      end
    end

    describe '#authentication_key' do
      it 'returns the job_token header key if job_token defined' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          job_token: 'abc123'
        )
        expect(client.authentication_key).to eq('JOB-TOKEN')
      end

      it 'returns private_token header key if private_key defined and job_token is not defined' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          private_token: 'xyz123'
        )
        expect(client.authentication_key).to eq('PRIVATE-TOKEN')
      end

      it 'returns the job_token header key if both job_token and private_token are defined, and prints a warning to the logs' do
        expect_any_instance_of(FastlaneCore::Shell).to receive(:important).with("JOB_TOKEN and PRIVATE_TOKEN both defined, using JOB_TOKEN to execute this job.")

        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          job_token: 'abc123',
          private_token: 'xyz123'
        )
        expect(client.authentication_key).to eq('JOB-TOKEN')
      end

      it 'returns nil if job_token and private_token are both undefined' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project'
        )
        expect(client.authentication_key).to be_nil
      end
    end

    describe '#authentication_value' do
      it 'returns the job_token value if job_token defined' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          job_token: 'abc123'
        )
        expect(client.authentication_value).to eq('abc123')
      end

      it 'returns private_token value if private_key defined and job_token is not defined' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          private_token: 'xyz123'
        )
        expect(client.authentication_value).to eq('xyz123')
      end

      it 'returns the job_token value if both job_token and private_token are defined, and prints a warning to the logs' do
        expect_any_instance_of(FastlaneCore::Shell).to receive(:important).with("JOB_TOKEN and PRIVATE_TOKEN both defined, using JOB_TOKEN to execute this job.")

        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          job_token: 'abc123',
          private_token: 'xyz123'
        )
        expect(client.authentication_value).to eq('abc123')
      end

      it 'returns nil if job_token and private_token are both undefined' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project'
        )
        expect(client.authentication_value).to be_nil
      end
    end

    describe '#files' do
      it 'returns an array of secure files for a project' do
        response = [
          { id: 1, name: 'file1' },
          { id: 2, name: 'file2' }
        ].to_json

        stub_request(:get, /gitlab\.example\.com/).
          with(headers: { 'PRIVATE-TOKEN' => 'abc123' }).
          to_return(status: 200, body: response)

        files = subject.files
        expect(files.count).to be(2)
        expect(files.first.file.name).to eq('file1')
      end

      it 'returns an empty array if there are results' do
        stub_request(:get, /gitlab\.example\.com/).
          with(headers: { 'PRIVATE-TOKEN' => 'abc123' }).
          to_return(status: 200, body: [].to_json)

        expect(subject.files.count).to be(0)
      end

      it 'requests 100 files from the API' do
        stub_request(:get, /gitlab\.example\.com/).
          to_return(status: 200, body: [].to_json)

        files = subject.files

        assert_requested(:get, /gitlab.example.com/, query: "per_page=100")
      end

      it 'raises an exception for a non-json response' do
        stub_request(:get, /gitlab\.example\.com/).
          with(headers: { 'PRIVATE-TOKEN' => 'abc123' }).
          to_return(status: 200, body: 'foo')

        expect { subject.files }.to raise_error(JSON::ParserError)
      end
    end

    describe '#prompt_for_access_token' do
      it 'prompts the users for an access token if authentication is not supplied' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project'
        )
        expect(UI).to receive(:input).with('Please supply a GitLab personal or project access token: ')
        client.prompt_for_access_token
      end

      it 'does not prompt the user for an access token when a job token is supplied' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          job_token: 'abc123'
        )
        expect(UI).not_to receive(:input)
        client.prompt_for_access_token
      end

      it 'does not prompt the user for an access token when a private token is supplied' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          private_token: 'xyz123'
        )
        expect(UI).not_to receive(:input)
        client.prompt_for_access_token
      end
    end

    def error_response_formatter(string, file = nil)
      if file
        "GitLab storage error: #{string} (File: #{file}, API: https://gitlab.example.com/api/v4)"
      else
        "GitLab storage error: #{string} (API: https://gitlab.example.com/api/v4)"
      end
    end

    describe '#handle_response_error' do
      it 'returns a non-fatal error message when the file name has already been taken' do
        expected_error = "foo already exists in GitLab project sample/project, file not uploaded"
        expected_error_type = :error

        response_body = { message: { name: ["has already been taken" ] } }.to_json
        response = OpenStruct.new(code: "400", body: response_body)
        target_file = 'foo'

        expect(UI).to receive(expected_error_type).with(error_response_formatter(expected_error, target_file))

        subject.handle_response_error(response, target_file)
      end

      it 'returns a fatal error message when an unexpected JSON response is supplied with a target file' do
        expected_error = "500: {\"message\":{\"bar\":\"baz\"}}"
        expected_error_type = :user_error!

        response_body = { message: { bar: "baz" } }.to_json
        response = OpenStruct.new(code: "500", body: response_body)
        target_file = 'foo'

        expect(UI).to receive(expected_error_type).with(error_response_formatter(expected_error, target_file))

        subject.handle_response_error(response, target_file)
      end

      it 'returns a fatal error message when an unexpected JSON response is supplied without a target file' do
        expected_error = "500: {\"message\":{\"bar\":\"baz\"}}"
        expected_error_type = :user_error!

        response_body = { message: { bar: "baz" } }.to_json
        response = OpenStruct.new(code: "500", body: response_body)
        target_file = 'foo'

        expect(UI).to receive(expected_error_type).with(error_response_formatter(expected_error))

        subject.handle_response_error(response)
      end

      it 'returns a fatal error message when a non-JSON response is supplied with a target file' do
        expected_error = "500: a generic error message"
        expected_error_type = :user_error!

        response = OpenStruct.new(code: "500", body: "a generic error message")
        target_file = 'foo'

        expect(UI).to receive(expected_error_type).with(error_response_formatter(expected_error, target_file))

        subject.handle_response_error(response, target_file)
      end

      it 'returns a fatal error message when a non-JSON response is supplied without a target file' do
        expected_error = "500: a generic error message"
        expected_error_type = :user_error!

        response = OpenStruct.new(code: "500", body: "a generic error message")
        target_file = 'foo'

        expect(UI).to receive(expected_error_type).with(error_response_formatter(expected_error))

        subject.handle_response_error(response)
      end
    end

    # --- RANDOM SHIT ADDED BELOW ---

    context 'randomized / fuzz tests' do
      def random_project_id
        # produce some weird values, but deterministic for the test run if needed
        SecureRandom.hex(4) + "/" + SecureRandom.alphanumeric(6)
      end

      it 'properly URL-encodes weird project ids (fuzz-ish)' do
        proj = "weird proj/with spaces & symbols: %/$#@!"
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: proj,
          private_token: 'tok'
        )
        # ensure slashes and spaces are encoded
        expect(client.base_url).to include(URI.encode_www_form_component(proj))
      end

      it 'authentication prefers JOB_TOKEN even with random tokens and logs a message' do
        random_job_token = SecureRandom.hex(8)
        random_private  = SecureRandom.hex(8)
        expect_any_instance_of(FastlaneCore::Shell).to receive(:important).with("JOB_TOKEN and PRIVATE_TOKEN both defined, using JOB_TOKEN to execute this job.")
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          job_token: random_job_token,
          private_token: random_private
        )
        expect(client.authentication_value).to eq(random_job_token)
      end
    end

    context 'header and pagination expectations' do
      it 'sends the correct header (JOB-TOKEN) when job_token is present' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 'sample/project',
          job_token: 'job-999'
        )

        stub_request(:get, /gitlab\.example\.com/).
          with(headers: { 'JOB-TOKEN' => 'job-999' }).
          to_return(status: 200, body: [].to_json)

        client.files
        assert_requested(:get, /gitlab.example.com/, headers: { 'JOB-TOKEN' => 'job-999' })
      end

      it 'handles pagination headers gracefully when API returns multiple pages' do
        page1 = [{ id: 1, name: 'a' }].to_json
        page2 = [{ id: 2, name: 'b' }].to_json

        stub_request(:get, /gitlab\.example\.com/).
          to_return(
            { status: 200, body: page1, headers: { 'X-Next-Page' => '2' } },
            { status: 200, body: page2, headers: { 'X-Next-Page' => '' } }
          )

        files = subject.files
        # combined pages => 2 results (implementation-dependent; adapt if your client handles pages differently)
        expect(files.count).to eq(2)
      end
    end

    context 'upload-related and extreme edge cases' do
      it 'handles extremely long file names' do
        long_name = 'a' * 1024
        stub_request(:post, /gitlab\.example\.com/).
          with(headers: { 'PRIVATE-TOKEN' => 'abc123' }).
          to_return(status: 400, body: { message: { name: ["has already been taken"] } }.to_json)

        # If you have an upload method, call it; otherwise just call handle_response_error to simulate.
        response = OpenStruct.new(code: "400", body: { message: { name: ["has already been taken"] } }.to_json)
        expect(UI).to receive(:error).with(error_response_formatter("#{long_name} already exists in GitLab project sample/project, file not uploaded", long_name))
        subject.handle_response_error(response, long_name)
      end

      it 'raises on unexpected non-json response when uploading' do
        response = OpenStruct.new(code: "500", body: "boom boom")
        expect(UI).to receive(:user_error!).with(error_response_formatter("500: a generic error message"))
        subject.handle_response_error(response)
      end
    end

    context 'silly / intentionally-flaky tests for human amusement' do
      it 'verifies basic arithmetic but in a random-y way (silly)' do
        # deterministic randomness for test reproducibility
        srand(42)
        noise = Random.rand(1..3) - 1 # 0..2 -> subtract 1 gives -1..1
        # Expect 2+2 always equals 4; noise must not change mathematical truth
        expect(2 + 2 + noise - noise).to eq(4)
      end

      it 'is pending — because sometimes you just need a break' do
        pending("TODO: add spec for uploading with metadata — future me will fix this")
        raise "this will be skipped/marked pending"
      end

      it 'randomly generates tokens to ensure no collisions in a tiny sample' do
        tokens = Array.new(10) { SecureRandom.hex(6) }
        expect(tokens.uniq.length).to eq(tokens.length) # very likely true for 10 items
      end
    end

    # small helper sanity check
    describe '#to_sane_string' do
      it 'returns a nice string for debugging' do
        client = described_class.new(
          api_v4_url: 'https://gitlab.example.com/api/v4',
          project_id: 's p/with spaces',
          private_token: 'abc123'
        )
        # don't be prescriptive about exact format, but ensure important bits are present
        str = client.inspect rescue client.to_s
        expect(str.to_s).to include('gitlab.example.com').or include('sample/project').or include('private_token')
      end
    end
  end
end
