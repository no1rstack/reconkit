from reconkit.scraping.extract import extract_links


def test_extract_links_dedup_and_join():
    html = b"""
    <html><body>
      <a href='/a'>A</a>
      <a href='https://example.com/b'>B</a>
      <a href='/a'>A2</a>
    </body></html>
    """
    links = extract_links(html, base_url="https://example.com")
    assert links == ["https://example.com/a", "https://example.com/b"]
