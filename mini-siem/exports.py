"""CSV export with spreadsheet formula neutralization for untrusted log text."""
def safe_csv(frame):
    result = frame.copy()
    def escape(value):
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + value
        if isinstance(value, str) and value.startswith(("\t", "\r", "\n")):
            return "'" + value
        return value
    for column in result.columns:
        result[column] = result[column].map(escape)
    return result.to_csv(index=False)
