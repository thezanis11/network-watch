import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Network Watch: offline flow analytics and incident correlation')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('benchmark')
    run = sub.add_parser('analyze')
    run.add_argument('capture', type=Path)
    run.add_argument('--format', choices=('zeek', 'eve'), default='zeek')
    run.add_argument('--model', type=Path)
    run.add_argument('--out', type=Path)
    args = parser.parse_args()
    from .benchmark import benchmark, analyze
    if args.command == 'benchmark':
        benchmark()
    else:
        analyze(args.capture, args.format, args.model, args.out)


if __name__ == '__main__':
    main()
