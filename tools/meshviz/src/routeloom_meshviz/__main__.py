"""`python -m routeloom_meshviz` starts the GUI; `--demo-capture` writes a synthetic capture without Qt."""
import argparse
import sys


def _scenario_main(argv):
    parser = argparse.ArgumentParser(prog='python -m routeloom_meshviz scenario')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('validate', help='static long-plan validation')
    p.add_argument('plan')
    p.add_argument('--api1-sock', help='daemon API1 unix socket (capacity.get)')

    p = sub.add_parser('run', help='run a scenario headless against a daemon')
    p.add_argument('plan')
    p.add_argument('--journal-dir', required=True)
    p.add_argument('--api1-sock', required=True)
    p.add_argument('--device-cmd',
                   help='shell template for power/reset: {op} {node} {bundle_digest}')
    p.add_argument('--site-dir', help='D03 provisioning site directory')
    p.add_argument('--bundles-dir', help='signed provisioning bundles directory')
    p.add_argument('--report-dir')
    p.add_argument('--tick-ms', type=int, default=100)

    p = sub.add_parser('resume', help='resume from a scenario journal')
    p.add_argument('journal')
    p.add_argument('--api1-sock', required=True)
    p.add_argument('--device-cmd')
    p.add_argument('--site-dir')
    p.add_argument('--bundles-dir')
    p.add_argument('--report-dir')
    p.add_argument('--tick-ms', type=int, default=100)

    args = parser.parse_args(argv)
    from .scenario_driver import run, validate_plan
    from .scenario import ScenarioError

    try:
        if args.cmd == 'validate':
            errors = validate_plan(args.plan, api1_path=args.api1_sock)
        else:
            errors = None
    except ScenarioError as exc:
        print(f'{exc.code}: {exc.detail}', file=sys.stderr)
        return 2
    if args.cmd == 'validate':
        for err in errors:
            print(f'  - {err}', file=sys.stderr)
        if errors:
            return 2
        print('plan valid')
        return 0

    try:
        if args.cmd == 'run':
            runner, summary = run(args.plan, journal_dir=args.journal_dir,
                                  api1_path=args.api1_sock,
                                  device_cmd=args.device_cmd,
                                  site_dir=args.site_dir,
                                  bundles_dir=args.bundles_dir,
                                  report_dir=args.report_dir,
                                  tick_ms=args.tick_ms)
        else:
            runner, summary = run(None, journal_dir=None,
                                  api1_path=args.api1_sock,
                                  device_cmd=args.device_cmd,
                                  site_dir=args.site_dir,
                                  bundles_dir=args.bundles_dir,
                                  report_dir=args.report_dir,
                                  resume_journal=args.journal,
                                  tick_ms=args.tick_ms)
    except ScenarioError as exc:
        print(f'{exc.code}: {exc.detail}', file=sys.stderr)
        return 2
    print(summary['state'])
    return 0 if summary['state'] == 'Completed' else 1


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
    if argv and argv[0] == 'scenario':
        return _scenario_main(argv[1:])
    # Qt is imported only for the GUI; headless model/capture code never needs it.
    from .ui.app import main as gui_main
    return gui_main(argv)


if __name__ == '__main__':
    sys.exit(main())
