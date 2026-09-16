package fingerprint

import (
	"fmt"
	"net"
)

// MaxBodyBytes 和 MaxBatchSize 约束每次请求的资源消耗，client 与 server 共用。
const MaxBodyBytes = 8 << 20
const MaxBatchSize = 1000

// ValidateBatch 区分输入格式错误与正常的未知指纹。空 Banner 合法，null 数组非法。
// 整批校验通过后再识别，避免发生一半成功、一半格式错误的含糊响应。
func ValidateBatch(inputs []Input) error {
	if inputs == nil {
		return fmt.Errorf("input must be a JSON array, not null")
	}
	if len(inputs) > MaxBatchSize {
		return fmt.Errorf("batch exceeds %d entries", MaxBatchSize)
	}
	for i, in := range inputs {
		if net.ParseIP(in.IP) == nil {
			return fmt.Errorf("entry %d: invalid IP", i)
		}
		if in.Port < 1 || in.Port > 65535 {
			return fmt.Errorf("entry %d: port must be 1-65535", i)
		}
	}
	return nil
}
