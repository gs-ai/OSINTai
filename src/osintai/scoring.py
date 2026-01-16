def rank_pages(page_scores):
    return sorted(page_scores, key=lambda x: x.get("score", 0), reverse=True)