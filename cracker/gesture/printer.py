# Adapted from https://github.com/sch3m4/androidpatternlock


def print_graphical_gesture(pattern: str) -> None:
    gesture: list[int | None] = [None, None, None, None, None, None, None, None, None]

    for index, num in enumerate(pattern, start=1):
        gesture[int(num)] = index
    print("Gesture:")
    for number in range(3):
        val: list[str | None] = [None, None, None]
        for j in range(3):
            val[j] = (
                " " if gesture[number * 3 + j] is None else str(gesture[number * 3 + j])
            )

        print("  -----  -----  -----")
        print(f"  | {val[0]} |  | {val[1]} |  | {val[2]} |  ")
        print("  -----  -----  -----")
