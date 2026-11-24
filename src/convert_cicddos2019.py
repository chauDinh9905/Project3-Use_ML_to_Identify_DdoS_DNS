"""
Chuyển CSV gốc CIC-DDoS2019 (ngày 01-12) sang Parquet, rồi in tóm tắt nhanh.
Chạy: python convert_cicddos2019.py --in-dir ./01-12 --out-dir ./parquet
Cần: pip install polars
Đọc dạng streaming nên dùng ít RAM; bỏ qua TFTP.csv (9.3 GB) vì không cần cho đề tài DNS.
"""
import argparse
from pathlib import Path
import polars as pl

# DNS + các giao thức reflection khác (cho leave-one-protocol-out ở tuần 9)
DEFAULT_FILES = ["DrDoS_DNS", "DrDoS_LDAP", "DrDoS_MSSQL", "DrDoS_NetBIOS",
                 "DrDoS_NTP", "DrDoS_SNMP", "DrDoS_SSDP", "DrDoS_UDP"]

# Cột giữ dạng chuỗi (định danh) — tuần 5 sẽ quyết định bỏ cột nào để tránh rò rỉ
STRING_COLS = {"Flow ID", "Source IP", "Destination IP", "Timestamp", "Label"}
DROP_COLS = {"Unnamed: 0", "SimillarHTTP"}


def convert(csv_path: Path, out_path: Path) -> None:
    # Đọc tất cả dạng chuỗi trước để tránh lỗi đoán kiểu (Infinity, NaN, số lẫn chữ)
    lf = pl.scan_csv(csv_path, infer_schema_length=0, low_memory=True)
    names = lf.collect_schema().names()
    lf = lf.rename({c: c.strip() for c in names})  # tên cột gốc có dấu cách ở đầu
    cols = [c.strip() for c in names if c.strip() not in DROP_COLS]
    exprs = []
    for c in cols:
        if c in STRING_COLS:
            exprs.append(pl.col(c).str.strip_chars())
        else:
            # "Infinity" -> inf, ô lỗi -> null; xử lý inf/null ở tuần 5
            exprs.append(pl.col(c).str.strip_chars().cast(pl.Float64, strict=False))
    lf = lf.select(exprs).with_columns(pl.lit(csv_path.stem).alias("source_file"))
    lf.sink_parquet(out_path, compression="zstd")


def summarize(out_dir: Path) -> None:
    lf = pl.scan_parquet(out_dir / "*.parquet")
    print("\n=== Số dòng theo file và nhãn ===")
    print(lf.group_by("source_file", "Label").len().sort("source_file", "len",
          descending=[False, True]).collect())

    dns = pl.scan_parquet(out_dir / "DrDoS_DNS.parquet")
    print("\n=== DrDoS_DNS: phân bố theo nhãn và cổng 53 ===")
    print(dns.group_by("Label").agg(
        pl.len().alias("rows"),
        (pl.col("Source Port") == 53).mean().alias("ti_le_src_port_53"),
        (pl.col("Destination Port") == 53).mean().alias("ti_le_dst_port_53"),
        pl.col("Protocol").mode().first().alias("protocol_pho_bien"),
    ).collect())
    print("\nKhoảng thời gian:", dns.select(
        pl.col("Timestamp").min().alias("dau"), pl.col("Timestamp").max().alias("cuoi")
    ).collect())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--files", nargs="*", default=DEFAULT_FILES)
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    for name in args.files:
        src, dst = args.in_dir / f"{name}.csv", args.out_dir / f"{name}.parquet"
        if dst.exists():
            print(f"Bỏ qua {name} (đã có Parquet)")
            continue
        if not src.exists():
            print(f"Không thấy {src}")
            continue
        print(f"Đang chuyển {name} ...", flush=True)
        convert(src, dst)
        print(f"  xong: {dst.stat().st_size / 1e6:.1f} MB")

    if (args.out_dir / "DrDoS_DNS.parquet").exists():
        summarize(args.out_dir)


if __name__ == "__main__":
    main()