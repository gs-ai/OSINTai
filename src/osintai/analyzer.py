def compute_page_signal(indicators: dict, analysis: dict):
    """Compute intelligence signal score for a page."""
    score = 0.0

    # Indicator counts
    score += min(len(indicators.get("emails", [])), 10) * 2.0
    score += min(len(indicators.get("phones", [])), 5) * 1.5
    score += min(len(indicators.get("btc_addresses", [])), 3) * 3.0
    score += min(len(indicators.get("eth_addresses", [])), 3) * 3.0
    score += min(len(indicators.get("social_handles", [])), 5) * 1.0

    # AI analysis scoring
    if analysis and isinstance(analysis, dict):
        # Risk flags - highest value intelligence indicators
        risk_flags = analysis.get("risk_flags", [])
        if isinstance(risk_flags, list):
            score += len(risk_flags) * 5.0  # 5 points per risk flag

        # Actionable leads - valuable intelligence
        actionable_leads = analysis.get("actionable_leads", [])
        if isinstance(actionable_leads, list):
            # Handle both list of strings and list of dicts
            if actionable_leads and isinstance(actionable_leads[0], dict):
                # List of dicts with "lead" key
                score += len([lead for lead in actionable_leads if isinstance(lead, dict) and "lead" in lead]) * 3.0
            else:
                # List of strings
                score += len(actionable_leads) * 3.0

        # Key entities - named entities of interest
        key_entities = analysis.get("key_entities", [])
        if isinstance(key_entities, list):
            score += min(len(key_entities), 10) * 1.0  # Up to 10 points for entities

        # Key locations - geographic intelligence
        key_locations = analysis.get("key_locations", [])
        if isinstance(key_locations, list):
            score += min(len(key_locations), 5) * 1.5  # Up to 7.5 points for locations

        # Keywords - topic relevance
        keywords = analysis.get("keywords", [])
        if isinstance(keywords, list):
            score += min(len(keywords), 20) * 0.5  # Up to 10 points for keywords

    return score
