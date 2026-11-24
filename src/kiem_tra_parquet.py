"""
Kiểm tra nhanh kết quả Bước 1: đủ file chưa, mỗi file bao nhiêu dòng/cột,
nhãn nào, bao nhiêu giá trị null/NaN/inf.
Chạy: python src/kiem_tra_parquet.py --dir data/parquet
"""
import argparse
from pathlib import Path
import polars as pl

EXPECTED = ["DrDoS_DNS", "DrDoS_LDAP", "DrDoS_MSSQL", "DrDoS_NetBIOS",
            "DrDoS_NTP", "DrDoS_SNMP", "DrDoS_SSDP", "DrDoS_UDP"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, type=Path)
    args = ap.parse_args()

    missing = [n for n in EXPECTED if not (args.dir / f"{n}.parquet").exists()]
    print("Thiếu file:", missing if missing else "không")

    for f in sorted(args.dir.glob("*.parquet")):
        lf = pl.scan_parquet(f)
        schema = lf.collect_schema()
        num_cols = [c for c, t in schema.items() if t == pl.Float64]
        stats = lf.select(
            pl.len().alias("so_dong"),
            pl.sum_horizontal([pl.col(c).is_null().sum() for c in num_cols]).alias("null"),
            pl.sum_horizontal([pl.col(c).is_nan().sum() for c in num_cols]).alias("nan"),
            pl.sum_horizontal([pl.col(c).is_infinite().sum() for c in num_cols]).alias("inf"),
        ).collect().row(0, named=True)
        labels = (lf.group_by("Label").len().sort("len", descending=True)
                    .collect().rows())
        print(f"\n{f.name}: {f.stat().st_size/1e6:.1f} MB, {stats['so_dong']:,} dòng, "
              f"{len(schema)} cột, null={stats['null']:,}, NaN={stats['nan']:,}, inf={stats['inf']:,}")
        for lab, n in labels:
            print(f"   {lab:<15} {n:>12,}")


if __name__ == "__main__":
    main()