def generate_explanation(url, prediction, confidence):
    """
    Temporary rule-based explanation.
    Later we will replace this with LLM output.
    """

    if prediction == "phishing":
        return f"The system detected suspicious characteristics in {url}. The model is {round(confidence*100,2)}% confident this is a phishing attempt. Users should avoid interacting with this link."
    else:
        return f"The link {url} appears legitimate based on current analysis with {round(confidence*100,2)}% confidence."