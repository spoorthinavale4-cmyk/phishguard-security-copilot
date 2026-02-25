import pandas as pd

LOG_PATH = "../data/simulated_click_logs.csv"

def check_siem_for_clicks(url):

    try:
        df = pd.read_csv(LOG_PATH)
        impacted = df[df["url_clicked"] == url]["user_email"].tolist()

        return impacted

    except:
        return []