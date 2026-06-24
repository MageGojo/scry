//! 设置页:根证书(一键 / 手动安装 + 信任检查)与 代理 / 抓包 控制。

use mage_ui::gpui::{ClipboardItem, Div};
use mage_ui::prelude::*;

use scry_proxy::tls_profile::TlsProfile;

use crate::cert;
use crate::logger::LogLevel;
use crate::state::{CaptureMode, CertStatus, ScryApp};
use crate::widgets::{divider, section_label};

impl ScryApp {
    /// 设置页主体(两张卡:根证书 / 代理与抓包)。
    pub fn settings_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;
        let path = cert::ca_path().to_string_lossy().to_string();

        let (status_color, status_label) = match self.cert_status {
            CertStatus::Unknown => (c.text_subtle, l.t("Unknown")),
            CertStatus::Checking => (c.warning, l.t("Checking…")),
            CertStatus::Trusted => (c.success, l.t("Trusted")),
            CertStatus::Untrusted => (c.danger, l.t("Not trusted")),
        };

        // ── 根证书卡 ──
        let ca_header = div()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .child(section_label(l.t("Root CA"), c, t))
            .child(
                div()
                    .text_size(t.font_size.sm)
                    .text_color(c.text_muted)
                    .child(l.t("Trust the Scry root CA to decrypt HTTPS")),
            );

        let path_row = DetailRow::new(IconName::Tag, l.t("Certificate path"))
            .value(path.clone())
            .trailing(
                IconButton::new("cert-copy-icon", IconName::Copy).on_click(cx.listener(
                    |this, _e, _w, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(
                            cert::ca_path().to_string_lossy().to_string(),
                        ));
                        this.cert_msg = Some("已复制证书路径".to_string());
                        cx.notify();
                    },
                )),
            );

        let status_row = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(Icon::new(IconName::Check).size(px(16.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(c.text_muted)
                            .child(l.t("Trust status")),
                    )
                    .child(StatusDot::new(status_color))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(status_color)
                            .child(status_label),
                    ),
            )
            .child(
                Button::new("cert-check", l.t("Check trust"))
                    .ghost()
                    .size(ButtonSize::Sm)
                    .icon(IconName::Refresh)
                    .on_click(cx.listener(|this, _e, _w, cx| this.check_cert(cx))),
            );

        let actions = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .flex_wrap()
            .child(
                Button::new(
                    "cert-install",
                    if self.cert_busy {
                        l.t("Installing…")
                    } else {
                        l.t("Install & trust (one-click)")
                    },
                )
                .icon(IconName::Check)
                .on_click(cx.listener(|this, _e, _w, cx| this.install_cert(cx))),
            )
            .child(
                Button::new("cert-reveal", l.t("Reveal in Finder"))
                    .ghost()
                    .icon(IconName::Folder)
                    .on_click(|_e, _w, _a| cert::reveal_in_finder()),
            )
            .child(
                Button::new("cert-open", l.t("Open with Keychain"))
                    .ghost()
                    .icon(IconName::Tag)
                    .on_click(|_e, _w, _a| cert::open_in_keychain()),
            )
            .child(
                Button::new(
                    "cert-export",
                    if self.cert_busy {
                        l.t("Exporting…")
                    } else {
                        l.t("Export installer (other devices)")
                    },
                )
                .ghost()
                .icon(IconName::Download)
                .on_click(cx.listener(|this, _e, _w, cx| this.export_cert_bundle(cx))),
            );

        let manual = div()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .child(section_label(l.t("Manual steps"), c, t))
            .child(step_line(l.t("1. Open Keychain Access and import ca.pem"), c, t))
            .child(step_line(l.t("2. Find Scry Root CA, set Trust to Always Trust"), c, t))
            .child(step_line(l.t("3. Re-run capture; HTTPS will decrypt"), c, t));

        // ── 多机共用同一根 CA(导出含私钥的 CA / 在另一台导入)──
        let sync_block = div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .child(section_label(l.t("Share one CA across devices"), c, t))
            .child(
                div()
                    .text_size(t.font_size.sm)
                    .text_color(c.text_muted)
                    .child(l.t("Export the CA (with private key) and import it on another computer, so multiple machines use the same root.")),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.danger)
                    .child(l.t("The identity file contains the private key — transfer it only between your own devices.")),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .flex_wrap()
                    .child(
                        Button::new("ca-export-identity", l.t("Export CA (with key)"))
                            .ghost()
                            .icon(IconName::Download)
                            .on_click(cx.listener(|this, _e, _w, cx| this.export_ca_identity(cx))),
                    )
                    .child(
                        Button::new("ca-import-identity", l.t("Import CA"))
                            .ghost()
                            .icon(IconName::Box)
                            .on_click(cx.listener(|this, _e, _w, cx| this.import_ca_identity(cx))),
                    ),
            );

        let mut ca_card = card(c, t)
            .child(ca_header)
            .child(divider(c))
            .child(path_row)
            .child(status_row)
            .child(actions);
        if let Some(msg) = &self.cert_msg {
            let ok = !msg.contains("失败") && !msg.contains("取消") && !msg.contains("占用");
            ca_card = ca_card.child(
                div()
                    .text_size(t.font_size.sm)
                    .text_color(if ok { c.success } else { c.danger })
                    .child(msg.clone()),
            );
        }
        ca_card = ca_card
            .child(divider(c))
            .child(manual)
            .child(divider(c))
            .child(sync_block);

        // ── 代理 / 抓包卡 ──
        let cap_color = if self.capturing { c.success } else { c.text_subtle };
        let mode_idx = CaptureMode::ALL
            .iter()
            .position(|m| *m == self.capture_mode)
            .unwrap_or(0);
        let view = cx.entity();
        let mode_seg = Segmented::new("cap-mode")
            .items(CaptureMode::ALL.map(|m| l.t(m.label())))
            .selected(mode_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.capture_mode = CaptureMode::ALL[i];
                    cx.notify();
                });
            });

        let mode_specific = if self.capture_mode == CaptureMode::Kernel {
            let no_if = if l.is_zh() { "(无可用网卡)" } else { "(no interface)" };
            let names: Vec<SharedString> = if self.ifaces.is_empty() {
                vec![SharedString::from(no_if)]
            } else {
                self.ifaces.iter().cloned().map(SharedString::from).collect()
            };
            let view_t = cx.entity();
            let view_s = cx.entity();
            let iface_select = Select::new("iface-select", names, self.iface_sel)
                .width(px(280.0))
                .open(self.iface_open)
                .on_toggle(move |_e, _w, app| {
                    view_t.update(app, |this, cx| {
                        this.iface_open = !this.iface_open;
                        cx.notify();
                    });
                })
                .on_select(move |i, _e, _w, app| {
                    view_s.update(app, |this, cx| {
                        this.iface_sel = i;
                        this.iface_open = false;
                        cx.notify();
                    });
                });
            div()
                .flex()
                .flex_col()
                .gap(t.space.sm)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(t.space.sm)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(t.space.sm)
                                .child(
                                    Icon::new(IconName::Globe)
                                        .size(px(16.0))
                                        .color(c.text_subtle),
                                )
                                .child(
                                    div()
                                        .text_size(t.font_size.sm)
                                        .text_color(c.text_muted)
                                        .child(l.t("Network interface")),
                                ),
                        )
                        .child(iface_select),
                )
                .child(
                    div()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(l.t(
                            "No Proxifier needed; sniffs your NIC directly. HTTPS shows SNI only.",
                        )),
                )
                .child(
                    Button::new("bpf-auth", l.t("Authorize capture (BPF)"))
                        .ghost()
                        .size(ButtonSize::Sm)
                        .icon(IconName::Check)
                        .on_click(cx.listener(|this, _e, _w, cx| this.authorize_bpf(cx))),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(t.space.sm)
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.0))
                                .child(
                                    div()
                                        .text_size(t.font_size.sm)
                                        .text_color(c.text_muted)
                                        .child(l.t("Save pcapng (Wireshark)")),
                                )
                                .child(
                                    div()
                                        .text_size(t.font_size.xs)
                                        .text_color(c.text_subtle)
                                        .child(l.t(
                                            "Also write raw L2/L3 frames to ~/.scry/*.pcapng",
                                        )),
                                ),
                        )
                        .child(
                            Switch::new("pcapng-toggle", self.pcapng_enabled)
                                .disabled(self.capturing)
                                .on_toggle(cx.listener(|this, _e, _w, cx| {
                                    this.pcapng_enabled = !this.pcapng_enabled;
                                    cx.notify();
                                })),
                        ),
                )
        } else {
            div()
                .flex()
                .flex_col()
                .gap(t.space.sm)
                .child(DetailRow::new(IconName::Globe, l.t("Proxy address")).value("127.0.0.1:8888"))
                .child(
                    div()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(l.t("Point Proxifier (or system proxy) to this address.")),
                )
                .child(
                    div()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(l.t("Behind Quantumult X / Surge? Use Proxifier to route the target process to Scry; add a Direct rule for Scry itself to avoid a loop.")),
                )
                .child(divider(c))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(t.space.sm)
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.0))
                                .child(
                                    div()
                                        .text_size(t.font_size.sm)
                                        .text_color(c.text_muted)
                                        .child(l.t("Upstream proxy (chain out)")),
                                )
                                .child(
                                    div()
                                        .text_size(t.font_size.xs)
                                        .text_color(c.text_subtle)
                                        .child(l.t(
                                            "Decrypted traffic exits via this proxy. Off = direct connect.",
                                        )),
                                ),
                        )
                        .child(
                            Switch::new("upstream-toggle", self.upstream_enabled).on_toggle(
                                cx.listener(|this, _e, _w, cx| {
                                    this.upstream_enabled = !this.upstream_enabled;
                                    this.push_log(
                                        LogLevel::Info,
                                        "upstream",
                                        if this.upstream_enabled {
                                            "上游代理已启用(解密流量经上游出网)"
                                        } else {
                                            "上游代理已关闭(直连出网)"
                                        },
                                    );
                                    cx.notify();
                                }),
                            ),
                        ),
                )
                .child(self.upstream_input.clone())
        };

        // TLS 指纹伪装下拉(影响 MITM 代理上游 + Repeater 重放)。
        let tls_names: Vec<SharedString> =
            TlsProfile::ALL.iter().map(|p| l.t(p.label())).collect();
        let view_tt = cx.entity();
        let view_ts = cx.entity();
        let tls_select = Select::new("tls-profile-select", tls_names, self.tls_profile_sel)
            .width(px(180.0))
            .open(self.tls_profile_open)
            .on_toggle(move |_e, _w, app| {
                view_tt.update(app, |this, cx| {
                    this.tls_profile_open = !this.tls_profile_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_ts.update(app, |this, cx| {
                    this.tls_profile_sel = i;
                    this.tls_profile_open = false;
                    scry_proxy::tls_profile::set_active(TlsProfile::ALL[i]);
                    cx.notify();
                });
            });
        let tls_row = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .min_w(px(0.0))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(c.text_muted)
                            .child(l.t("TLS fingerprint")),
                    )
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(l.t("Mimic a browser ClientHello upstream (proxy & repeater)")),
                    ),
            )
            .child(tls_select);

        // 当前档的**真实**上游指纹(让 rustls 真吐 ClientHello 算出,缓存)。以 JA4 为准(稳定)。
        let ja4_text = scry_proxy::fingerprint::fingerprint_for_cached(
            TlsProfile::ALL[self.tls_profile_sel],
        )
        .map(|f| f.ja4)
        .unwrap_or_else(|| "—".to_string());
        let tls_block = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .child(tls_row)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(t.space.sm)
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(l.t("Upstream JA4")),
                    )
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_muted)
                            .child(ja4_text),
                    ),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(l.t("JA4 is the real upstream fingerprint (order-stable). JA3 varies per connection; an exact browser match needs BoringSSL.")),
            );

        let proxy_card = card(c, t)
            .child(section_label(l.t("Proxy & Capture"), c, t))
            .child(divider(c))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(t.space.sm)
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(c.text_muted)
                            .child(l.t("Capture mode")),
                    )
                    .child(mode_seg),
            )
            .child(mode_specific)
            .child(divider(c))
            .child(tls_block)
            .child(divider(c))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(StatusDot::new(cap_color))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .text_size(t.font_size.sm)
                            .text_color(cap_color)
                            .child(if self.capturing {
                                format!(
                                    "{} · {} {}",
                                    l.t("Capturing"),
                                    self.flows.len(),
                                    l.t("Captured flows")
                                )
                            } else {
                                l.t("Stopped").to_string()
                            }),
                    )
                    .child(
                        Button::new(
                            "settings-capture",
                            l.t(if self.capturing {
                                "Stop capture"
                            } else {
                                "Start capture"
                            }),
                        )
                        .variant(if self.capturing {
                            ButtonVariant::Danger
                        } else {
                            ButtonVariant::Primary
                        })
                        .icon(IconName::Zap)
                        .on_click(cx.listener(|this, _e, _w, cx| this.toggle_capture(cx))),
                    ),
            );

        div()
            .id("settings-scroll")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .items_center()
            .p(t.space.xl)
            .child(
                div()
                    .w(px(720.0))
                    .max_w(px(720.0))
                    .flex()
                    .flex_col()
                    .gap(t.space.lg)
                    .child(ca_card)
                    .child(proxy_card),
            )
    }
}

/// 一张设置卡(实色面板 + 描边 + 圆角)。
fn card(c: ThemeColors, t: Tokens) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(t.space.md)
        .p(t.space.lg)
        .rounded(t.radius.xl)
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
}

/// 手动步骤的一行(弱化等宽)。
fn step_line(text: impl Into<SharedString>, c: ThemeColors, t: Tokens) -> impl IntoElement {
    div()
        .text_size(t.font_size.sm)
        .text_color(c.text_subtle)
        .child(text.into())
}
