package mock

import (
	"gochopchop/core"
)

var FakeOutputStatusCode = core.Output{
	URL:         "http://problems",
	Endpoint:    FakePlugin.Endpoint,
	Name:        FakeCheckStatusCode200.Name,
	Severity:    FakeCheckStatusCode200.Severity,
	Remediation: FakeCheckStatusCode200.Remediation,
}

var FakeOutputMatchOne = core.Output{
	URL:         "http://problems",
	Endpoint:    FakePlugin.Endpoint,
	Name:        FakeCheckMatchOne.Name,
	Severity:    FakeCheckMatchOne.Severity,
	Remediation: FakeCheckMatchOne.Remediation,
}
var FakeOutputMatchAll = core.Output{
	URL:         "http://problems",
	Endpoint:    FakePlugin.Endpoint,
	Name:        FakeCheckMatchAll.Name,
	Severity:    FakeCheckMatchAll.Severity,
	Remediation: FakeCheckMatchAll.Remediation,
}

var FakeOutputNotMatch = core.Output{
	URL:         "http://problems",
	Endpoint:    FakePlugin.Endpoint,
	Name:        FakeCheckNotMatch.Name,
	Severity:    FakeCheckNotMatch.Severity,
	Remediation: FakeCheckNotMatch.Remediation,
}

var FakeOutputNoHeaders = core.Output{
	URL:         "http://problems",
	Endpoint:    FakePlugin.Endpoint,
	Name:        FakeCheckNoHeaders.Name,
	Severity:    FakeCheckNoHeaders.Severity,
	Remediation: FakeCheckNoHeaders.Remediation,
}

var FakeOutputHeaders = core.Output{
	URL:         "http://problems",
	Endpoint:    FakePlugin.Endpoint,
	Name:        FakeCheckHeaders.Name,
	Severity:    FakeCheckHeaders.Severity,
	Remediation: FakeCheckHeaders.Remediation,
}

var FakeOutput = []core.Output{
	FakeOutputStatusCode,
	FakeOutputHeaders,
	FakeOutputNoHeaders,
	FakeOutputMatchAll,
	FakeOutputMatchOne,
	FakeOutputNotMatch,
}
