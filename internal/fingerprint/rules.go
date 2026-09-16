package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
)

// Rule 定义 JSON 规则格式；正则对象仅在内存中编译，不参与配置序列化。
type Rule struct {
	Name         string  `json:"name"`
	Pattern      string  `json:"pattern"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product"`
	VersionGroup int     `json:"version_group"`
	OSPattern    string  `json:"os_pattern"`
	Confidence   float64 `json:"confidence"`
	re           *regexp.Regexp
	osRE         *regexp.Regexp
}

// Load 在启动时校验并编译外部规则。规则错误阻止启动，避免服务带着无效规则运行。
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&rules); err != nil {
		return nil, err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("rules must contain one JSON array")
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("rules must not be empty")
	}
	names := make(map[string]bool, len(rules))
	for i := range rules {
		r := &rules[i]
		if r.Name == "" || r.Pattern == "" || r.Protocol == "" || r.Confidence < 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("invalid rule %d", i)
		}
		if names[r.Name] {
			return nil, fmt.Errorf("duplicate rule name: %s", r.Name)
		}
		names[r.Name] = true
		r.re, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}
		if r.VersionGroup < 0 || r.VersionGroup > r.re.NumSubexp() {
			return nil, fmt.Errorf("rule %s: invalid version group", r.Name)
		}
		if r.OSPattern != "" {
			r.osRE, err = regexp.Compile(r.OSPattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s OS: %w", r.Name, err)
			}
		}
	}
	return &Engine{rules: rules}, nil
}
