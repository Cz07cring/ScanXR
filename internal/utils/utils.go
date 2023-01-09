package utils

func RemoveDuplicate(list []string) []string {
	var set []string
	//
	hashSet := make(map[string]struct{})
	for _, i2 := range list {
		hashSet[i2] = struct{}{}
	}

	for s2 := range hashSet {
		if s2 == "" {
			continue
		}
		set = append(set, s2)
	}
	//fmt.Println(set)
	return set
}
