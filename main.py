import sys
from listing import list_processes
from behaviour_collector import (
    collect_all_behaviours,
    collect_behaviour_by_pid,
    display_behaviour,
)


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <command>")
        print("\nCommands:")
        print("  list                 List running applications")
        print("  collect              Collect behaviour data for all applications")
        print("  collect <pid>        Collect behaviour data for a specific PID")
        print("  collect --no-net     Collect behaviour data without network info")
        return

    command = sys.argv[1]

    if command == "list":
        list_processes()

    elif command == "collect":
        include_network = "--no-net" not in sys.argv
        # If a PID is provided, collect for that process only
        pid_arg = None
        for arg in sys.argv[2:]:
            if arg.isdigit():
                pid_arg = int(arg)
                break

        if pid_arg is not None:
            print(f"\nCollecting behaviour data for PID {pid_arg}...")
            data = collect_behaviour_by_pid(pid_arg, include_network=include_network)
            if data:
                display_behaviour([data])
            else:
                print(f"  Could not collect data for PID {pid_arg} (not found or access denied).\n")
        else:
            print("\nCollecting behaviour data for all visible applications...")
            data_list = collect_all_behaviours(include_network=include_network)
            display_behaviour(data_list)

    else:
        print("Invalid command.")
        print("Available commands: list, collect")


if __name__ == "__main__":
    main()
