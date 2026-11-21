def describe(x):
    match x:
        case 1:
            return "one"
        case 2 | 3:
            return "two or three"
        case _:
            return "other"
