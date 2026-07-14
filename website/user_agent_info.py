import pandas as pd
from user_agents import parse

def parse_user_agent(ua_string, session_id):
    if pd.isna(ua_string):  # Check if the user-agent string is NaN
        return {
            'session_id': session_id,
            'browser_family': None,
            'browser_version': None,
            'os_family': None,
            'os_version': None,
            'device_family': None,
            'is_mobile': None,
            'is_tablet': None,
            'is_pc': None,
            # 'is_bot': None Handled in separate is_bot.py following code updates from Taein.
        }
    else:
        user_agent = parse(ua_string)
        return {
            'session_id': session_id,
            'browser_family': user_agent.browser.family,
            'browser_version': user_agent.browser.version_string,
            'os_family': user_agent.os.family,
            'os_version': user_agent.os.version_string,
            'device_family': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            # 'is_bot': user_agent.is_bot
        }
