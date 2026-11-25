"""
Bước 3 - Tiền xử lý và chọn đặc trưng.

Đầu vào : data/parquet/DrDoS_*.parquet (8 file của Bước 1)
Đầu ra  : data/processed/clean_all.parquet   - mọi file, đã làm sạch + khử trùng (dùng lại ở Bước 5)
          data/processed/dns_binary.parquet  - DrDoS_DNS + BENIGN, có cột chia tập (dùng ở Bước 4)
          reports/features.json              - danh sách đặc trưng cuối cùng và lý do loại từng cột
          (bản tóm tắt in ra màn hình: nên lưu bằng tee vào reports/buoc3_tien_xu_ly.txt)

Chạy: python src/tien_xu_ly.py --in-dir data/parquet --out-dir data/processed --reports reports \
          | tee reports/buoc3_tien_xu_ly.txt
"""
import argparse
import json
from pathlib import Path

import numpy as np
import polars as pl

FILES = ["DrDoS_DNS", "DrDoS_LDAP", "DrDoS_MSSQL", "DrDoS_NetBIOS",
         "DrDoS_NTP", "DrDoS_SNMP", "DrDoS_SSDP", "DrDoS_UDP"]
ATTACKER_IP = "172.16.0.5"          # IP tấn công ngày 01-12 (xác nhận ở EDA Bước 2)
# Cột định danh: giữ lại để tham chiếu / chia theo thời gian, KHÔNG dùng làm đặc trưng
ID_COLS = ["Flow ID", "Source IP", "Source Port", "Destination IP",
           "Destination Port", "Timestamp"]
META_COLS = ["Label", "source_file"]
# Cột bị lỗi tràn số hoặc trùng lặp của CICFlowMeter (xem EDA Bước 2, mục 2)
DROP_FIXED = {
    "Fwd Header Length.1": "cột trùng với Fwd Header Length",
    "Fwd Header Length": "giá trị âm do lỗi tràn số CICFlowMeter",
    "Bwd Header Length": "giá trị âm do lỗi tràn số CICFlowMeter",
    "min_seg_size_forward": "giá trị âm do lỗi tràn số CICFlowMeter",
}
RATE_COLS = ["Flow Bytes/s", "Flow Packets/s"]
CORR_THRESHOLD = 0.98
SPLIT = (0.6, 0.2, 0.2)             # train / val / test


def section(t):
    print("\n" + "=" * 72 + f"\n{t}\n" + "=" * 72, flush=True)


def clean_one(path: Path, feats: list[str]) -> pl.DataFrame:
    """Làm sạch một file và khử trùng lặp bên trong file (streaming, ít RAM)."""
    lf = pl.scan_parquet(path)
    is_attack = pl.col("Label") != "BENIGN"
    suspicious = is_attack & (pl.col("Source IP") != ATTACKER_IP)
    if path.stem == "DrDoS_DNS":
        suspicious = suspicious | (is_attack & (pl.col("Protocol") != 17))
    rate_bad = pl.any_horizontal([pl.col(c).is_infinite() | pl.col(c).is_null()
                                  for c in RATE_COLS])
    lf = lf.with_columns(
        suspicious.alias("nghi_sai_nhan"),
        rate_bad.alias("rate_inf"),
        *[pl.when(pl.col(c).is_infinite()).then(None).otherwise(pl.col(c)).alias(c)
          for c in RATE_COLS],
    ).with_columns(
        pl.struct(feats + ["rate_inf"]).hash(seed=0).alias("h")
    )
    other = ["source_file"] + [c for c in ID_COLS if c != "Timestamp"] + ["rate_inf"] + feats
    # Mỗi (vector đặc trưng, nhãn) chỉ giữ 1 dòng; nghi_sai_nhan = True khi MỌI bản trùng đều đáng nghi.
    # Timestamp = lần xuất hiện ĐẦU TIÊN của vector (chuỗi "YYYY-MM-DD HH:MM:SS.ffffff" so sánh được).
    return (lf.group_by("h", "Label")
              .agg([pl.col(c).first() for c in other]
                   + [pl.col("Timestamp").min(),
                      pl.col("nghi_sai_nhan").all(), pl.len().alias("so_ban_trung")])
              .collect(engine="streaming"))


def stratified_split(labels: np.ndarray, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    out = np.empty(len(labels), dtype=object)
    for lab in np.unique(labels):
        idx = np.flatnonzero(labels == lab)
        rng.shuffle(idx)
        a = int(len(idx) * SPLIT[0])
        b = a + int(len(idx) * SPLIT[1])
        out[idx[:a]], out[idx[a:b]], out[idx[b:]] = "train", "val", "test"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--reports", default=Path("reports"), type=Path)
    ap.add_argument("--seed", default=42, type=int)
    ap.add_argument("--mi-sample", default=30_000, type=int)
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.reports.mkdir(parents=True, exist_ok=True)
    pl.Config.set_tbl_rows(40)
    pl.Config.set_tbl_cols(-1)
    pl.Config.set_tbl_width_chars(160)

    schema = pl.scan_parquet(args.in_dir / "DrDoS_DNS.parquet").collect_schema()
    all_num = [c for c, t in schema.items()
               if t == pl.Float64 and c not in ID_COLS and c not in META_COLS]
    feats = [c for c in all_num if c not in DROP_FIXED]
    removed = {c: DROP_FIXED[c] for c in DROP_FIXED if c in schema}
    removed.update({c: "cột định danh (rò rỉ), chỉ dùng tham chiếu"
                    for c in ID_COLS if c in schema})

    # 1. Làm sạch + khử trùng lặp từng file
    section("1. Làm sạch và khử trùng lặp trong từng file")
    parts, rows = [], []
    for name in FILES:
        p = args.in_dir / f"{name}.parquet"
        if not p.exists():
            print(f"Không thấy {p}, bỏ qua")
            continue
        n_before = pl.scan_parquet(p).select(pl.len()).collect().item()
        df = clean_one(p, feats)
        parts.append(df)
        rows.append((name, n_before, df.height))
        print(f"{name:<14} {n_before:>12,} -> {df.height:>9,} dòng "
              f"(giữ {df.height / n_before:.2%})", flush=True)
    data = pl.concat(parts, how="vertical_relaxed")
    del parts

    # BENIGN có thể trùng giữa các file -> khử trùng lần nữa trên toàn bộ
    before = data.height
    other = [c for c in data.columns
             if c not in ("h", "Label", "nghi_sai_nhan", "so_ban_trung", "Timestamp")]
    data = (data.group_by("h", "Label", maintain_order=True)
                .agg([pl.col(c).first() for c in other]
                     + [pl.col("Timestamp").min(),
                        pl.col("nghi_sai_nhan").all(), pl.col("so_ban_trung").sum()]))
    print(f"\nKhử trùng giữa các file (BENIGN trùng giữa nhiều file): {before:,} -> {data.height:,} dòng")

    # 2. Vector đặc trưng mang nhiều nhãn khác nhau
    #    - BENIGN lẫn tấn công: nhiễu nhãn thật sự -> loại
    #    - chỉ giữa các kiểu tấn công (vd DNS và LDAP): vẫn là tấn công -> giữ, gắn cờ cho Bước 5
    section("2. Vector đặc trưng mang nhiều nhãn (xung đột)")
    multi = (data.group_by("h")
                 .agg(pl.col("Label").unique().sort().alias("nhan"),
                      pl.col("Label").n_unique().alias("k"),
                      (pl.col("Label") == "BENIGN").any().alias("co_benign"))
                 .filter(pl.col("k") > 1))
    print(f"Số vector xung đột: {multi.height:,} "
          f"(BENIGN lẫn tấn công: {multi.filter(pl.col('co_benign')).height:,}; "
          f"chỉ giữa các kiểu tấn công: {multi.filter(~pl.col('co_benign')).height:,})")
    if multi.height:
        print(multi.with_columns(pl.col("nhan").list.join(" | ")).group_by("nhan").len()
                   .sort("len", descending=True).head(15))
    bad = multi.filter(pl.col("co_benign"))["h"].implode()
    att_conf = multi.filter(~pl.col("co_benign"))["h"].implode()
    n_bad = data.filter(pl.col("h").is_in(bad)).height
    data = (data.filter(~pl.col("h").is_in(bad))
                .with_columns(pl.col("h").is_in(att_conf).alias("xung_dot_tan_cong")))
    print(f"Đã loại {n_bad:,} dòng thuộc vector BENIGN lẫn tấn công. Còn {data.height:,} dòng.")
    print(f"Dòng tấn công trùng vector với kiểu tấn công khác (giữ, gắn cờ xung_dot_tan_cong): "
          f"{data.filter(pl.col('xung_dot_tan_cong')).height:,}")
    print(data.filter(pl.col("xung_dot_tan_cong")).group_by("Label").len().sort("len", descending=True))

    # 3. Thống kê sau làm sạch
    section("3. Số dòng theo file và nhãn sau làm sạch (nghi_sai_nhan = có thể gán nhãn sai)")
    print(data.group_by("source_file", "Label", "nghi_sai_nhan").len()
              .sort("source_file", "Label", "nghi_sai_nhan"))
    print("\nTổng BENIGN (gom từ mọi file):",
          f"{data.filter(pl.col('Label') == 'BENIGN').height:,}")
    data.write_parquet(args.out_dir / "clean_all.parquet", compression="zstd")
    print(f"Đã lưu {args.out_dir / 'clean_all.parquet'}")

    # 4. Tập DNS + BENIGN và chia tập
    section("4. Tập DNS + BENIGN và chia train/val/test")
    dns = data.filter(pl.col("Label").is_in(["DrDoS_DNS", "BENIGN"]))
    dns = dns.with_columns(pl.col("Timestamp").str.to_datetime(
        "%Y-%m-%d %H:%M:%S%.f", strict=False).alias("ts"))
    labels = dns["Label"].to_numpy()
    split_rand = stratified_split(labels, args.seed)
    # Chia theo thời gian: tấn công theo thứ tự thời gian (60% đầu train, 20% val, 20% cuối test);
    # BENIGN rải khắp ngày nên giữ cách chia ngẫu nhiên có phân tầng.
    split_time = split_rand.copy()
    att_idx = np.flatnonzero(labels == "DrDoS_DNS")
    order = att_idx[np.argsort(dns["ts"].to_numpy()[att_idx], kind="stable")]
    a = int(len(order) * SPLIT[0])
    b = a + int(len(order) * SPLIT[1])
    split_time[order[:a]], split_time[order[a:b]], split_time[order[b:]] = "train", "val", "test"
    dns = dns.with_columns(pl.Series("split_ngau_nhien", split_rand.astype(str)),
                           pl.Series("split_thoi_gian", split_time.astype(str)))
    for col in ["split_ngau_nhien", "split_thoi_gian"]:
        print(f"\n{col}:")
        print(dns.group_by(col, "Label").len()
                 .pivot(on="Label", index=col, values="len").sort(col))
    t = dns.filter(pl.col("Label") == "DrDoS_DNS").group_by("split_thoi_gian").agg(
        pl.col("ts").min().alias("tu"), pl.col("ts").max().alias("den")).sort("tu")
    print("\nKhung thời gian của tấn công trong split_thoi_gian:")
    print(t)

    # 5. Chọn đặc trưng (chỉ dựa trên tập train ngẫu nhiên để tránh rò rỉ)
    section("5. Chọn đặc trưng (tính trên train của split_ngau_nhien)")
    train = dns.filter(pl.col("split_ngau_nhien") == "train")
    cand = feats + ["rate_inf"]
    nun = train.select([pl.col(c).n_unique().alias(c) for c in cand]).row(0, named=True)
    const = [c for c in cand if nun[c] <= 1]
    for c in const:
        removed[c] = "hằng số trên tập train"
    cand = [c for c in cand if c not in const]
    print(f"Cột hằng số ({len(const)}): {const}")

    X = train.select([pl.col(c).cast(pl.Float64) for c in cand]).to_numpy()
    med = np.nanmedian(X, axis=0)
    X = np.where(np.isnan(X), med, X)
    with np.errstate(invalid="ignore", divide="ignore"):
        corr = np.corrcoef(X, rowvar=False)
    corr = np.nan_to_num(corr)
    kept, pairs = [], []
    for j, c in enumerate(cand):
        hit = next((k for k in kept if abs(corr[j, cand.index(k)]) > CORR_THRESHOLD), None)
        if hit is None:
            kept.append(c)
        else:
            pairs.append((c, hit, round(float(corr[j, cand.index(hit)]), 4)))
            removed[c] = f"tương quan |r|>{CORR_THRESHOLD} với '{hit}'"
    print(f"\nLoại do tương quan cao ({len(pairs)} cột):")
    for c, k, r in pairs:
        print(f"  {c:<32} ~ {k:<32} r={r}")
    print(f"\nSố đặc trưng còn lại: {len(kept)}")

    # Xếp hạng tham khảo bằng mutual information
    try:
        from sklearn.feature_selection import mutual_info_classif
        tr = train.select(kept + ["Label"])
        n = min(args.mi_sample, tr.height)
        tr = tr.sample(n, seed=args.seed) if n < tr.height else tr
        Xs = tr.select([pl.col(c).cast(pl.Float64) for c in kept]).to_numpy()
        Xs = np.where(np.isnan(Xs), np.nanmedian(Xs, axis=0), Xs)
        y = (tr["Label"] != "BENIGN").to_numpy().astype(int)
        mi = mutual_info_classif(Xs, y, random_state=args.seed)
        rank = sorted(zip(kept, mi), key=lambda x: -x[1])
        print(f"\nTop 20 đặc trưng theo mutual information (mẫu {n:,} dòng train):")
        for c, v in rank[:20]:
            print(f"  {c:<32} {v:.4f}")
        mi_rank = {c: round(float(v), 5) for c, v in rank}
    except ImportError:
        print("Chưa cài scikit-learn, bỏ qua mutual information")
        mi_rank = {}

    out = dns.drop("ts")
    out.write_parquet(args.out_dir / "dns_binary.parquet", compression="zstd")
    with open(args.reports / "features.json", "w", encoding="utf-8") as f:
        json.dump({"features": kept, "removed": removed, "mutual_info": mi_rank,
                   "corr_threshold": CORR_THRESHOLD, "seed": args.seed},
                  f, ensure_ascii=False, indent=2)
    section("Hoàn tất")
    print(f"- {args.out_dir / 'dns_binary.parquet'}: {out.height:,} dòng")
    print(f"- {args.reports / 'features.json'}: {len(kept)} đặc trưng, {len(removed)} cột bị loại")


if __name__ == "__main__":
    main()