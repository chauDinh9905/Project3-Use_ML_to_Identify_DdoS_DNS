"""
Bước 2 - EDA trên DrDoS_DNS.parquet (thư mục 01-12).
Chạy: python src/eda_dns.py --file data/parquet/DrDoS_DNS.parquet --out reports | tee reports/buoc2_eda.txt
Cần: polars, matplotlib, numpy. Tính toán dạng lazy, chỉ nạp vài cột khi vẽ hình.
"""
import argparse
from datetime import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import polars as pl

ID_COLS = ["Flow ID", "Source IP", "Source Port", "Destination IP",
           "Destination Port", "Timestamp"]
NON_FEAT = set(ID_COLS) | {"Label", "source_file"}
# Các đặc trưng chính để so sánh BENIGN và tấn công (chỉ dùng cột nào có trong file)
KEY_FEATS = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
             "Total Length of Fwd Packets", "Fwd Packet Length Max",
             "Fwd Packet Length Mean", "Packet Length Mean", "Average Packet Size",
             "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean"]
# Khung giờ tấn công DNS theo trang UNB (ngày 01/12/2018)
UNB_START, UNB_END = time(10, 52), time(11, 5)


def section(title):
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, type=Path)
    ap.add_argument("--out", default=Path("reports"), type=Path)
    ap.add_argument("--sample", default=50_000, type=int,
                    help="số dòng tấn công lấy mẫu để vẽ hình")
    ap.add_argument("--seed", default=42, type=int)
    args = ap.parse_args()
    fig_dir = args.out / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    pl.Config.set_tbl_rows(40)
    pl.Config.set_tbl_cols(-1)
    pl.Config.set_fmt_str_lengths(45)
    pl.Config.set_tbl_width_chars(160)

    lf = pl.scan_parquet(args.file)
    schema = lf.collect_schema()
    feats = [c for c, t in schema.items() if c not in NON_FEAT and t == pl.Float64]
    key = [c for c in KEY_FEATS if c in schema]
    print(f"File: {args.file}  |  {len(schema)} cột, trong đó {len(feats)} cột đặc trưng số")
    print("Không có trong file (bỏ qua):", [c for c in KEY_FEATS if c not in schema] or "không")

    # 1. Tổng quan nhãn
    section("1. Số dòng theo nhãn")
    print(lf.group_by("Label").len().with_columns(
        (pl.col("len") / pl.col("len").sum() * 100).round(4).alias("phan_tram")
    ).sort("len", descending=True).collect())

    # 2. Chất lượng dữ liệu từng cột
    section("2. Cột có giá trị null / inf / âm (chỉ liệt kê cột có vấn đề)")
    row = lf.select(
        [pl.col(c).is_null().sum().alias(f"{c}|null") for c in feats]
        + [pl.col(c).is_infinite().sum().alias(f"{c}|inf") for c in feats]
        + [(pl.col(c) < 0).sum().alias(f"{c}|am") for c in feats]
    ).collect().row(0, named=True)
    q = pl.DataFrame({"cot": [c for c in feats],
                      "null": [row[f"{c}|null"] for c in feats],
                      "inf": [row[f"{c}|inf"] for c in feats],
                      "am": [row[f"{c}|am"] for c in feats]})
    print(q.filter((pl.col("null") > 0) | (pl.col("inf") > 0) | (pl.col("am") > 0)))

    # 3. Cột hằng số
    section("3. Cột hằng số (chỉ có 1 giá trị) - ứng viên bỏ ở Bước 3")
    nun = lf.select([pl.col(c).n_unique().alias(c) for c in feats]).collect().row(0, named=True)
    const = [c for c in feats if nun[c] <= 1]
    print(f"{len(const)} cột:", const)

    # 4. Trùng lặp theo vector đặc trưng
    section("4. Dòng trùng lặp (cùng vector đặc trưng, bỏ cột định danh)")
    h = lf.select(pl.struct(feats).hash().alias("h"), "Label").collect()
    print(f"Tổng dòng: {h.height:,}  |  vector đặc trưng khác nhau: {h['h'].n_unique():,}  "
          f"|  dòng trùng: {h.height - h['h'].n_unique():,}")
    conflict = h.group_by("h").agg(pl.col("Label").n_unique().alias("k")).filter(pl.col("k") > 1)
    print(f"Vector đặc trưng xuất hiện với >1 nhãn (BENIGN lẫn tấn công): {conflict.height:,}")
    print(h.group_by("Label").agg(
        (pl.col("h").is_duplicated().sum()).alias("dong_trung_trong_nhan")))
    del h, conflict

    # 5. Giao thức, cổng, IP
    section("5. Giao thức theo nhãn (6 = TCP, 17 = UDP, 0 = khác)")
    print(lf.group_by("Label", "Protocol").len().sort("Label", "len",
          descending=[False, True]).collect())
    for col in ["Source Port", "Destination Port", "Source IP", "Destination IP"]:
        if col not in schema:
            continue
        section(f"5. Top 10 '{col}' theo nhãn (+ số giá trị khác nhau)")
        stat = lf.group_by("Label").agg(pl.col(col).n_unique().alias("so_gia_tri_khac_nhau"))
        print(stat.collect())
        print(lf.group_by("Label", col).len().sort("len", descending=True)
                .group_by("Label", maintain_order=True).head(10).sort("Label").collect())

    # 6. Thời gian
    section("6. Thời gian theo nhãn")
    ts = pl.col("Timestamp").str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False)
    tlf = lf.select("Label", ts.alias("ts"))
    print(tlf.group_by("Label").agg(pl.col("ts").min().alias("dau"),
                                    pl.col("ts").max().alias("cuoi"),
                                    pl.col("ts").is_null().sum().alias("khong_doc_duoc")).collect())
    print(f"\nSố dòng trong/ngoài khung tấn công DNS theo UNB ({UNB_START}–{UNB_END}):")
    print(tlf.with_columns(
        pl.col("ts").dt.time().is_between(UNB_START, UNB_END).alias("trong_khung_UNB")
    ).group_by("Label", "trong_khung_UNB").len().sort("Label", "trong_khung_UNB").collect())
    per_min = (tlf.with_columns(pl.col("ts").dt.truncate("1m").alias("phut"))
                  .group_by("phut", "Label").len().sort("phut").collect())
    print("\nSố flow mỗi phút (xem hình buoc2_theo_thoi_gian.png):")
    print(per_min.pivot(on="Label", index="phut", values="len").fill_null(0).sort("phut"))

    fig, ax = plt.subplots(figsize=(11, 4))
    for lab in per_min["Label"].unique().sort():
        d = per_min.filter(pl.col("Label") == lab)
        ax.plot(d["phut"].to_list(), d["len"].to_list(), marker="o", ms=3, label=lab)
    ax.set_yscale("log")
    ax.set_ylabel("Số flow mỗi phút (thang log)")
    ax.set_title("DrDoS_DNS.csv: số flow theo thời gian")
    ax.legend()
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(fig_dir / "buoc2_theo_thoi_gian.png", dpi=130)
    plt.close(fig)

    # 7. Hướng luồng
    section("7. Tỉ lệ flow KHÔNG có gói chiều ngược (Total Backward Packets = 0)")
    if "Total Backward Packets" in schema:
        print(lf.group_by("Label").agg(
            (pl.col("Total Backward Packets") == 0).mean().round(4).alias("ti_le_mot_chieu")
        ).collect())

    # 8. Thống kê đặc trưng chính (inf coi như thiếu)
    section("8. Trung vị, P5, P95 của đặc trưng chính theo nhãn (bỏ inf)")
    clean = [pl.when(pl.col(c).is_infinite()).then(None).otherwise(pl.col(c)).alias(c) for c in key]
    base = lf.select(["Label"] + clean)
    for c in key:
        print(f"\n-- {c}")
        print(base.group_by("Label").agg(
            pl.col(c).quantile(0.05).alias("P5"),
            pl.col(c).median().alias("trung_vi"),
            pl.col(c).quantile(0.95).alias("P95"),
        ).sort("Label").collect())

    # 9. Hình phân phối: toàn bộ BENIGN + mẫu tấn công
    benign = base.filter(pl.col("Label") == "BENIGN").collect()
    attack = base.filter(pl.col("Label") != "BENIGN").collect()
    attack = attack.sample(min(args.sample, attack.height), seed=args.seed)
    n = len(key)
    ncol = 3
    nrow = int(np.ceil(n / ncol))
    fig, axes = plt.subplots(nrow, ncol, figsize=(5 * ncol, 3.3 * nrow))
    for ax, c in zip(np.ravel(axes), key):
        for d, lab in [(benign, "BENIGN"), (attack, "DrDoS_DNS (mẫu)")]:
            v = d[c].drop_nulls().to_numpy()
            v = np.log10(v[v > 0]) if (v > 0).any() else np.array([])
            if v.size:
                ax.hist(v, bins=60, alpha=0.55, density=True, label=lab)
        ax.set_title(c, fontsize=10)
        ax.set_xlabel("log10(giá trị > 0)")
    for ax in np.ravel(axes)[n:]:
        ax.axis("off")
    np.ravel(axes)[0].legend()
    fig.tight_layout()
    fig.savefig(fig_dir / "buoc2_phan_phoi_dac_trung.png", dpi=120)
    plt.close(fig)
    print(f"\nĐã lưu hình vào {fig_dir}/ (BENIGN: {benign.height:,} dòng, "
          f"tấn công: mẫu {attack.height:,} dòng)")


if __name__ == "__main__":
    main()