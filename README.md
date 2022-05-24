# mongo-logs-exporter

## Configuration

You will need Atlas API keys taken from the Atlas Console

        export ATLAS_USERNAME="<PUBLIC_API_KEY>"
        export ATLAS_APIKEY="<PRIVATE_API_KEY>"

You will need to define a bucket to track `cursors` and write `logs` for logstash to ingest

        export ATLAS_LOG_BUCKET="my-state-bucket"

Optionally you can configure the log level

        export LOG_LEVEL="info"

You will also need to set up standard AWS credentials for `boto3` to use, for example

        AWS_SECRET_ACCESS_KEY=""
        AWS_ACCESS_KEY_ID=""

Or

        AWS_PROFILE="abc"

Or

        eval $(assume-role ops-admin)

If you would like to set a custom time for the period between when the code is run then use

        export SLEEP_SECS="<PERIOD_VALUE_IN_SECONDS>"         -       Defaults to 60s

If you would like to set a custom time for the window the code collects the mongodb atlas logs then use

        export <GROUP/ORG>_LOGS_TIME_WINDOW="<WINDOW_VALUE_IN_SECONDS>"        -       Defaults to 86400s (1 day)

If you would like to set a custom time for the window the code collects the mongodb atlas logs then use

        export <MONGODB / AUDIT>_LOGS_TIME_WINDOW="<WINDOW_VALUE_IN_UNIX_TIME_IN_SECONDS>"        -       Defaults to 86400s (1 day)

If you would like to set a custom time for the window the code collects database access history logs then use

        export ACCESS_HISTORY_TIME_WINDOW="<WINDOW_VALUE_IN_UNIX_TIME_IN_MILLISECONDS>"         -       Defaults to 2592000000ms (30 days)

If you would like to set a custom size of data to send to the s3 bucket for the mongodb atlas logs then use

        export <MONGODB / AUDIT>LOGS_S3_CHUNK_SIZE="<CHUNK_SIZE>"        -       Defaults to 1000

If you would like to set a custom size of data to send to the s3 bucket for the database access history then use

        export ACCESS_HISTORY_S3_CHUNK_SIZE="<CHUNK_SIZE>"         -       Defaults to 1000

Due to the memory limitations of the pod, env variables exist to limit how much of the gzip data is unzipped at a given pass

        export MONGODB_LOGS_ARRAY_SIZE="<UNZIPPED_ARRAY_SIZE_DESIRED_VALUE>"         -       Defaults to 500

## Dev Startup

You will need Python 3 (version 3.7.0) to run this code, this can be done via the below:

	pyenv install 3.7.0

You will need pip to install python modules. To install pip run the following command:

        sudo easy_install pip

To install the correct version requirements for the modules run the following command:

	pip install -r requirements-dev.txt

## To run

You will need python 3. To change your version of python, follow this link:

Use this command to run the code:

        python -m atlas_log.get_latest

Or

        docker build -t ndap_atlas_logs_exporter .
        docker run --rm -it ndap_atlas_logs_exporter

## To run tests

        pytest atlas_log/<test_file>.py

Or to run all tests

        pytest -v --cov=atlas_log


## Black formatting instructions

To install Black, use the command:

	brew install black

To run Black as a formatting tool, cd into the repository you plan to format and enter the command:

	black .

After formatting is complete, commit and push the changes.
