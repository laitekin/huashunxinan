// Package fingerprint 根据已有 Banner 执行被动识别，与 HTTP、日志和存储解耦。
package fingerprint

// Engine 的规则在构造后只读，可供多个 HTTP 请求并发使用。
type Engine struct{ rules []Rule }

// RuleCount 返回已加载规则数，供启动日志记录。
func (e *Engine) RuleCount() int { return len(e.rules) }

// Identify 按配置顺序寻找首条命中规则。具体软件规则应排在通用协议规则之前。
// 不依据端口猜测软件；空、截断和未知 Banner 均返回正常的 unknown 结果。
func (e *Engine) Identify(in Input) Result {
	out := Result{IP: in.IP, Port: in.Port, Protocol: "unknown"}
	for _, r := range e.rules {
		match := r.re.FindStringSubmatch(in.Banner)
		if match == nil {
			continue
		}
		out.Protocol, out.Product, out.Confidence = r.Protocol, r.Product, r.Confidence
		if r.VersionGroup > 0 {
			out.Version = match[r.VersionGroup]
		}
		if r.osRE != nil {
			out.OSHint = r.osRE.FindString(in.Banner)
		}
		return out
	}
	return out
}
