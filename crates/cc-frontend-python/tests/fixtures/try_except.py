def safe_div(a, b):
    try:
        return a / b
    except ZeroDivisionError as e:
        return None
    except (TypeError, ValueError):
        return -1
