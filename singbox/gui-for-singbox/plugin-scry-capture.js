/**
 * Scry 抓包配合插件 · GUI.for.SingBox
 *
 * 【写法对标官方 plugin-relay-proxy-helper】
 * 不再依赖插件级 on::generate 触发器 —— 实测该触发器会被 GUI 在加载时剔除
 * (plugins.yaml 里只剩 on::manual),onGenerate 从未执行、抓包链路从未注入。
 * 改为像 relay 那样【生成一段 onGenerate 混入脚本】,一键写入当前配置的
 * 「设置 → 混入和脚本 → 脚本操作」(profile.script.code);GUI 生成内核配置时
 * 必定执行该脚本,把 Scry 的 MITM 串进流量链路。
 *
 * 链路:
 *   任意软件
 *     │  (sing-box TUN 在网络层接管)
 *     ▼
 *   sing-box ──route(客户端入站, tcp)──▶ outbound "scry" (127.0.0.1:8888  Scry MITM 解密+落盘)
 *                                              │  Scry 上游 = SCRY_UPSTREAM
 *                                              ▼
 *                                      inbound "scry-upstream-in" (mixed 127.0.0.1:8899)
 *                                              │  按原有路由(国内直连 / 境外走节点),天然防回环
 *                                              ▼
 *                                          你选中的订阅节点 ──▶ 真实服务器
 *
 * 为什么不会回环:Scry 解密后把「到目标的连接」交回新增的 scry-upstream-in 入站,
 *   该入站不匹配「客户端入站 → scry」这条抓包规则(inbound 不同),会落到原有
 *   geosite/geoip 路由 → 节点出网。Scry 与内核之间走 127.0.0.1 回环,不经 TUN。
 *
 * 配置项(右键插件「配置插件」可改,未设则用默认):
 *   MitmAddr       Scry MITM(http 代理)地址            默认 127.0.0.1:8888
 *   UpstreamPort   新增 mixed 入站端口 = Scry 上游回流口  默认 8899
 *   UpstreamScheme Scry 上游协议(socks5/http,仅影响提示与复制的命令) 默认 socks5
 *   CaptureCN      是否连国内/直连流量一起抓             默认 false(只抓境外)
 *   TunInbound     被接管流量的 TUN 入站 tag             默认 tun-in
 *   AutoRun        内核启动时自动拉起 Scry(命令行)      默认 false
 *   ScryCommand    AutoRun 用的 scry_proxy 可执行文件绝对路径
 */

const SCRY_OUTBOUND_TAG = 'scry'
const UPSTREAM_INBOUND_TAG = 'scry-upstream-in'
const PID_FILE = 'data/third/scry/pid.txt'

const DEFAULT = {
  mitmAddr: '127.0.0.1:8888',
  upstreamHost: '127.0.0.1',
  upstreamPort: '8899',
  upstreamScheme: 'socks5',
  tunInbound: 'tun-in',
  captureCN: false
}

/**
 * 生成要写进配置「脚本操作」的 onGenerate 混入脚本(纯字符串)。
 * 顶层具名导出 —— 便于离线 node 测试其产物逻辑;GUI 只用 default 导出,不受影响。
 * @param {{mitmHost:string,mitmPort:number,upstreamHost:string,upstreamPort:number,tunInbound:string,captureCN:boolean}} c
 * @returns {string}
 */
export function buildCaptureScript(c) {
  const mitmHost = String(c.mitmHost || '127.0.0.1')
  const mitmPort = Number(c.mitmPort) || 8888
  const upstreamHost = String(c.upstreamHost || DEFAULT.upstreamHost)
  const upstreamPort = Number(c.upstreamPort) || 8899
  const tunInbound = String(c.tunInbound || DEFAULT.tunInbound)
  const captureCN = !!c.captureCN

  // 注意:模板内部的脚本一律用单引号,避免与外层反引号/${} 冲突;
  // 只有下面这几处 ${...} 是“此刻把配置值内联进生成脚本”,是有意为之。
  return `// === Scry 抓包混入脚本(由「Scry 抓包配合」插件生成,可重复覆盖)===
// 作用:生成内核配置时,把客户端流量路由进 Scry MITM 解密抓包,解密后经 Scry 上游
//       回流到本脚本新增的 mixed 入站,再按你原有路由(订阅节点)出网。幂等、防回环。
const onGenerate = async (config) => {
  const SCRY_OUTBOUND_TAG = '${SCRY_OUTBOUND_TAG}'
  const UPSTREAM_INBOUND_TAG = '${UPSTREAM_INBOUND_TAG}'
  const MITM_HOST = '${mitmHost}'
  const MITM_PORT = ${mitmPort}
  const UPSTREAM_HOST = '${upstreamHost}'
  const UPSTREAM_PORT = ${upstreamPort}
  const TUN_INBOUND = '${tunInbound}'
  const CAPTURE_CN = ${captureCN}

  if (!config || typeof config !== 'object') return config
  config.inbounds = Array.isArray(config.inbounds) ? config.inbounds : []
  config.outbounds = Array.isArray(config.outbounds) ? config.outbounds : []
  config.route = config.route && typeof config.route === 'object' ? config.route : {}
  config.route.rules = Array.isArray(config.route.rules) ? config.route.rules : []

  // 幂等:先清掉本脚本上次注入的入站/出站/路由,避免重复
  config.inbounds = config.inbounds.filter((i) => i && i.tag !== UPSTREAM_INBOUND_TAG)
  config.outbounds = config.outbounds.filter((o) => o && o.tag !== SCRY_OUTBOUND_TAG)
  config.route.rules = config.route.rules.filter((r) => !(r && r.outbound === SCRY_OUTBOUND_TAG))

  // 抓包规则要覆盖的「客户端入站」:此刻已剔除上次注入的回流口,余下即用户真实入站
  // (TUN 模式 = tun-in / 系统代理模式 = mixed-in 等),再并上 TUN_INBOUND 兜底。
  // 绝不含回流口 scry-upstream-in,否则 Scry 回流的流量会再次命中本规则 → 死循环。
  let clientInbounds = Array.from(
    new Set(
      config.inbounds
        .map((i) => i && i.tag)
        .filter((t) => typeof t === 'string' && t !== UPSTREAM_INBOUND_TAG)
        .concat(TUN_INBOUND ? [TUN_INBOUND] : [])
    )
  )
  if (clientInbounds.length === 0) clientInbounds = [TUN_INBOUND]

  // 1) 回流入站(mixed:http/socks5 通吃)= Scry 解密后的上游回流口
  config.inbounds.push({
    type: 'mixed',
    tag: UPSTREAM_INBOUND_TAG,
    listen: UPSTREAM_HOST,
    listen_port: UPSTREAM_PORT
  })

  // 2) scry 出站 = Scry 的 MITM(http 代理),sing-box 把要抓的流量发给它解密
  config.outbounds.push({
    type: 'http',
    tag: SCRY_OUTBOUND_TAG,
    server: MITM_HOST,
    server_port: MITM_PORT
  })

  // 3) 抓包路由:客户端入站(TUN 或系统代理 mixed-in)的 TCP 流量 → scry
  //    QUIC/UDP 不走(http 出站不支持 UDP;QUIC 一般已被 block,应用回退 TCP 正好便于抓包)
  let captureRule
  const cnTags = CAPTURE_CN
    ? []
    : (config.route.rule_set || [])
        .map((rs) => rs && rs.tag)
        .filter((t) => typeof t === 'string')
        .filter((t) => /private/i.test(t) || (/cn/i.test(t) && !t.includes('!')))

  if (cnTags.length) {
    // 只抓客户端入站上「非国内/非私网」的 TCP(逻辑与 + 反选 rule_set);国内/私网仍走原有直连
    captureRule = {
      type: 'logical',
      mode: 'and',
      rules: [{ inbound: clientInbounds }, { network: 'tcp' }, { rule_set: cnTags, invert: true }],
      action: 'route',
      outbound: SCRY_OUTBOUND_TAG
    }
  } else {
    // 抓客户端入站上所有 TCP
    captureRule = {
      action: 'route',
      inbound: clientInbounds,
      network: 'tcp',
      outbound: SCRY_OUTBOUND_TAG
    }
  }

  // 插到第一条带 rule_set 的路由之前 —— 让 sniff / hijack-dns / quic-block 先执行,
  // 也确保本规则先于原有 geosite 路由命中「客户端」流量(回流入站因 inbound 不同不会命中)。
  let idx = config.route.rules.findIndex(
    (r) =>
      r &&
      (r.rule_set ||
        (r.type === 'logical' && Array.isArray(r.rules) && r.rules.some((x) => x && x.rule_set)))
  )
  if (idx < 0) idx = config.route.rules.length
  config.route.rules.splice(idx, 0, captureRule)

  return config
}
`
}

/** @type {EsmPlugin} */
export default (Plugin) => {
  const P = Plugin || {}

  // 读取配置(带默认值与清洗)
  const conf = () => {
    const mitmAddr = String(P.MitmAddr || DEFAULT.mitmAddr).trim()
    const sep = mitmAddr.lastIndexOf(':')
    const mhost = sep > 0 ? mitmAddr.slice(0, sep) : '127.0.0.1'
    const mport = sep > 0 ? mitmAddr.slice(sep + 1) : '8888'
    return {
      mitmHost: mhost || '127.0.0.1',
      mitmPort: Number(mport) || 8888,
      upstreamHost: DEFAULT.upstreamHost,
      upstreamPort: Number(String(P.UpstreamPort || DEFAULT.upstreamPort).trim()) || 8899,
      upstreamScheme: String(P.UpstreamScheme || DEFAULT.upstreamScheme).trim() || 'socks5',
      tunInbound: String(P.TunInbound || DEFAULT.tunInbound).trim() || 'tun-in',
      captureCN: P.CaptureCN != null ? !!P.CaptureCN : DEFAULT.captureCN,
      autoRun: !!P.AutoRun,
      scryCommand: String(P.ScryCommand || '').trim()
    }
  }

  const upstreamURL = (c) => `${c.upstreamScheme}://${DEFAULT.upstreamHost}:${c.upstreamPort}`

  // 选择要写入抓包脚本的配置(profile)
  const selectProfile = async () => {
    const profilesStore = Plugins.useProfilesStore()
    const list = (profilesStore && profilesStore.profiles) || []
    if (!list.length) {
      Plugins.message.error('没有可用的配置(profile),请先在「配置」页创建一个')
      throw 'no-profile'
    }
    if (list.length === 1) return list[0]
    return await Plugins.picker.single(
      '请选择要写入 Scry 抓包脚本的配置',
      list.map((v) => ({ label: v.name, value: v })),
      [list[0]]
    )
  }

  // 预览脚本 + 复制 / 覆盖写入当前配置的「脚本操作」(对标 relay 的 displayConfigScript)
  const displayConfigScript = (profile, configScript) => {
    const profilesStore = Plugins.useProfilesStore()
    const { ref, h } = Vue
    const had = !!(profile && profile.script && String(profile.script.code || '').trim())
    const previewComponent = {
      template: `
        <div class="pr-8">
          <Card>
            <div class="flex justify-between items-start gap-12 rounded px-12 py-8">
              <div class="flex-1" style="line-height: 1.6">
                点右侧 <b>复制脚本</b> 到剪贴板,粘到该配置的
                “设置 → 混入和脚本 → 脚本操作”里;或点 <b>覆盖写入</b> 直接写进当前配置。
                <div v-if="had" class="text-12 mt-4" style="color:#ff6b6b">
                  注意:当前配置已存在脚本操作,“覆盖写入”会替换它。若有自定义脚本请改用“复制脚本”手动合并。
                </div>
              </div>
              <div style="flex:0 0 auto; display:flex; flex-direction:column; gap:6px;">
                <Button @click="onCopy" type="primary" title="将脚本复制到剪贴板">复制脚本</Button>
                <Button @click="onOverWrite" type="link" title="直接覆盖到当前配置的脚本操作">覆盖写入</Button>
              </div>
            </div>
            <CodeViewer v-model="code" lang="javascript"
              style="min-height:340px; width:100%; border-radius:6px; overflow:hidden;" />
          </Card>
        </div>`,
      setup() {
        const code = ref(configScript)
        const onOverWrite = async () => {
          profile.script = profile.script || {}
          profile.script.code = configScript
          await profilesStore.editProfile(profile.id, profile)
          Plugins.message.info('Scry 抓包脚本已写入配置「' + (profile.name || profile.id) + '」')
        }
        const onCopy = async () => {
          await Plugins.ClipboardSetText(code.value)
          Plugins.message.info('脚本已复制到剪贴板')
        }
        return { code, had, onOverWrite, onCopy }
      }
    }
    const modal = Plugins.modal(
      {
        title: 'Scry 抓包脚本预览',
        submit: false,
        cancelText: '关闭',
        afterClose: () => modal.destroy()
      },
      { default: () => h(previewComponent) }
    )
    modal.open()
  }

  // 生成脚本并打开预览
  const openUI = async (profile) => {
    const c = conf()
    const script = buildCaptureScript(c)
    displayConfigScript(profile, script)
  }

  /* 触发器:手动运行 —— 选配置 → 生成并预览抓包脚本 */
  const onRun = async () => {
    const profile = await selectProfile()
    await openUI(profile)
    return 0
  }

  /* 右键「配置」卡片:添加 Scry 抓包(context.profiles) */
  const addScryCapture = async (profile) => {
    await openUI(profile)
    return 0
  }

  /* 触发器:on::core::started —— 可选,自动拉起 Scry(命令行) */
  const onCoreStarted = async () => {
    const c = conf()
    if (!c.autoRun || !c.scryCommand) return 0
    try {
      await Plugins.ExecBackground(
        c.scryCommand,
        ['proxy', '--upstream', upstreamURL(c)],
        () => {},
        () => {},
        { PidFile: PID_FILE }
      )
      Plugins.message && Plugins.message.success('[Scry] 已自动拉起:' + c.scryCommand)
      return 1
    } catch (e) {
      Plugins.message && Plugins.message.warn('[Scry] 自动拉起失败:' + (e && e.message ? e.message : e))
      return 0
    }
  }

  /* 触发器:on::core::stopped —— 可选,停掉自动拉起的 Scry */
  const onCoreStopped = async () => {
    const c = conf()
    if (!c.autoRun) return 0
    try {
      const pid = await Plugins.ReadFile(PID_FILE).catch(() => '')
      if (pid) await Plugins.KillProcess(Number(pid)).catch(() => {})
    } catch (e) {
      /* 忽略 */
    }
    return 2
  }

  const helpText = () => {
    const c = conf()
    return [
      'Scry × sing-box 链式抓包(抓任意软件)',
      '',
      '链路:任意软件 → sing-box TUN → 出站 scry(' + c.mitmHost + ':' + c.mitmPort + ',MITM 解密+落盘)',
      '      → Scry 上游 ' + upstreamURL(c) + ' → 入站 ' + UPSTREAM_INBOUND_TAG,
      '      → 按你选中的订阅节点出网。保留全部节点,不抢系统代理。',
      '',
      '用法(本插件不靠 on::generate,改为生成混入脚本):',
      '1) 右键插件「生成抓包脚本并写入配置」(或点运行按钮)→ 选配置 → 覆盖写入 / 复制到',
      '   该配置「设置 → 混入和脚本 → 脚本操作」。GUI 生成配置时会执行它,串入 Scry。',
      '2) 右键「安装根证书到系统信任」,按提示在终端执行(抓任意软件必须)。',
      '3) 启动 Scry,上游指到本脚本入站:',
      '   · 图形界面 scry_app:先 export SCRY_UPSTREAM=' + upstreamURL(c) + ' 再启动',
      '   · 命令行:scry_proxy proxy --upstream ' + upstreamURL(c),
      '4) 开启 TUN 并(重新)启动内核,打开任意软件,解密流量会出现在 Scry。',
      '',
      '说明 / 排错:',
      '- 证书 pinning(部分大厂自有域名)、微信 MMTLS 等:任何 MITM 都解不开,握手秒断属正常;验证用 curl https://example.com。',
      '- QUIC/HTTP3 若被 block,应用回退 TCP,正好便于抓包。',
      c.captureCN
        ? '- 当前模式:国内/直连流量也一起抓。'
        : '- 当前模式:只抓境外(走代理)流量;国内/私网直连不抓(配置项 CaptureCN 可改)。'
    ].join('\n')
  }

  /* 菜单:生成抓包脚本并写入配置(与运行按钮同) */
  const GenerateScript = async () => {
    const profile = await selectProfile()
    await openUI(profile)
    return 0
  }

  /* 菜单:查看说明 */
  const ShowHelp = async () => {
    await Plugins.alert('Scry 抓包配合插件', helpText())
    return 0
  }

  /* 菜单:复制 Scry 启动命令 */
  const CopyStartCmd = async () => {
    const c = conf()
    const cli = (c.scryCommand || 'scry_proxy') + ' proxy --upstream ' + upstreamURL(c)
    const gui = 'export SCRY_UPSTREAM=' + upstreamURL(c) + ' && open -a scry_app'
    await Plugins.ClipboardSetText(cli)
    await Plugins.alert(
      'Scry 启动命令(命令行已复制到剪贴板)',
      ['命令行(已复制):', cli, '', '图形界面(scry_app):', gui].join('\n')
    )
    return 0
  }

  /* 菜单:安装根证书到系统信任(命令复制到剪贴板,终端执行) */
  const InstallCA = async () => {
    const cmd = 'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.scry/ca.pem'
    const verify = 'security verify-cert -c ~/.scry/ca.pem -p ssl'
    await Plugins.ClipboardSetText(cmd)
    await Plugins.alert(
      '安装 Scry 根证书到系统信任(命令已复制)',
      [
        '在终端执行(已复制到剪贴板):',
        cmd,
        '',
        '校验(看到 successful 即可):',
        verify,
        '',
        '说明:抓任意软件需系统信任 Scry 根 CA,否则目标会拒绝 MITM 证书、握手失败。'
      ].join('\n')
    )
    return 0
  }

  const onInstall = async () => {
    await Plugins.alert('Scry 抓包配合插件 · 已安装', helpText())
    return 0
  }
  const onUninstall = async () => 0

  return {
    onRun,
    addScryCapture,
    onCoreStarted,
    onCoreStopped,
    onInstall,
    onUninstall,
    GenerateScript,
    ShowHelp,
    CopyStartCmd,
    InstallCA
  }
}
