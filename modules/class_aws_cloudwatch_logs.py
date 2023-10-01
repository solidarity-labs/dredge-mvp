import datetime

class CloudWatchLogGroup:
    def __init__(self, region, log_group_name, log_streams):
        self.region = region
        self.log_group_name = log_group_name
        self.log_streams = log_streams


    @classmethod
    def constructor(cls, session, log_group_name):
        log_group_client = session.client('logs')
        streams = log_group_client.describe_log_streams(logGroupName=log_group_name)
        log_streams = []

        current_region = session.region_name
        for log in streams['logStreams']:
            log_streams.append(log['logStreamName'])

        return cls(current_region, log_group_name, log_streams)


    def get_cloudwatch_logs(cls, session, start_date, end_date):
        start_time = datetime.datetime.strptime(start_date, '%Y-%m-%d')
        start_time_ms = int(start_time.timestamp() * 1000)

        end_time = datetime.datetime.strptime(end_date, '%Y-%m-%d')
        end_time_ms = int(end_time.timestamp() * 1000)

        logs_client = session.client('logs')
        events = []
        # Print the log stream names
        if cls.log_streams:
            for log_stream in cls.log_streams:
                # Retrieve the CloudWatch logs
                response = logs_client.get_log_events(
                    logGroupName=cls.log_group_name,
                    logStreamName=log_stream,
                    startTime=start_time_ms,
                    endTime=end_time_ms
                )

                # Print the log events
                if 'events' in response:
                    for event in response['events']:
                        events.append(event)
                        print(f"{event['message']}")

        return events


    def get_log_stream_log(cls, session, start_date, end_date, log_stream):
        start_time = datetime.datetime.strptime(start_date, '%Y-%m-%d')
        start_time_ms = int(start_time.timestamp() * 1000)

        end_time = datetime.datetime.strptime(end_date, '%Y-%m-%d')
        end_time_ms = int(end_time.timestamp() * 1000)

        logs_client = session.client('logs')
        events = []
        response = logs_client.get_log_events(
            logGroupName=cls.log_group_name,
            logStreamName=log_stream,
            startTime=start_time_ms,
            endTime=end_time_ms
        )

        # Print the log events
        if 'events' in response:
            for event in response['events']:
                events.append(event)
                print(f"{event['message']}")
