package detect

// All returns every registered detector. Detectors append themselves here
// as they are implemented.
func All() []Detector {
	return []Detector{
		PoisoningDetector{},
		UnicodeDetector{},
		SecretsDetector{},
		SensitiveParamsDetector{},
	}
}
