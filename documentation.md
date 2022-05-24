NDAP-Logs-Exporter-Documentation

This piece of documentation has been created as a general overview of how the Logs-Exporter API works, giving a brief overview of the main API and how the additional modules tie in and the functionality they bring.

# get_latest.py
The get_latest.py is the entry point for the API, it is where the polling time is determined (how often the API is called), as well as which functions are called. The default polling value is set to 60 seconds.

# atlas_api.py
This is the main module which holds the functions for requesting the logs respectively, looping through the group and orgs.

### mk_auth() 

function authenticates the atlas account through the environment variables which are set using the export command. 

### ensure_no_missing_history

This function asserts a warning if there are more results than the number of results the page can hold.

### get_org_events

These two functions grab events specifically after the min date has been specified with 500 items per page. This also ties into the missing history function. The results converts the get_request into json format and filters the results array.

Logging returns information about the running process which can be useful when working with the API.

# write_events.py
This module contains the functions which write the logs retrieved to the S3 bucket.

### append_heartbeat

Appends a heartbeat to the events. This is to verify the function is working accordingly even if there are no events being passed through.

### _write_events_

This function writes the log data to an S3 bucket corresponding to the environment variable ATLAS_LOG_BUCKET

### write_org_events & write_group_events

Appends the heartbeat to the end of the events initially.
Writes the events with a unique name through the  `now.timestamp` attribute.

# high_watermark.py
This module sets the watermark which determines at which point logs were last retrieved to ensure logs are not repeatedly stored into the S3 bucket creating copies. There are two parameters for this:

`min_date`  and  `last_ids`  

This is because two different events could have the exact same time so to ensure zero overlap there must a second field type to differentiate events, last_ids.

# Running the program
1. `python -m atlas_log.get_latest.py`

This command will execute the program 

# Test Modules
The test modules including the test_harness_test.py contain tests for the functions defined in their counterparts and are used for test coverage and trying exception edge cases. It is worth noting that in order to create unit tests for our S3 function we have imported moto, which allows us to mimic S3 resource attributes without actually having to create anything. 

To utilise moto annotations are required above the function such as  `@moto.mock_s3`
