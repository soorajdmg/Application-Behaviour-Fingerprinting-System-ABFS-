import sys
from listing import list_processes


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py list")
        return

    command = sys.argv[1]

    if command == "list":
        list_processes()
    else:
        print("Invalid command.")
        print("Available command: list")


if __name__ == "__main__":
    main()
