"""`python -m routeloom_meshviz` starts the GUI; `--demo-capture` writes a synthetic capture without Qt."""
import argparse
import sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == '--demo-capture':
        parser = argparse.ArgumentParser(prog='python -m routeloom_meshviz --demo-capture')
        parser.add_argument('--demo-capture', dest='path', required=True)
        parser.add_argument('--nodes', type=int, default=8)
        parser.add_argument('--seconds', type=int, default=120)
        args = parser.parse_args(argv)
        from .demo import write_demo_capture
        write_demo_capture(args.path, count=args.nodes, duration_s=args.seconds)
        print(args.path)
        return 0
    # Qt is imported only for the GUI; headless model/capture code never needs it.
    from .ui.app import main as gui_main
    return gui_main(argv)


if __name__ == '__main__':
    sys.exit(main())
