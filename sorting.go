package main

type ByDate []Entry

func (e ByDate) Len() int      { return len(e) }
func (e ByDate) Swap(i, j int) { e[i], e[j] = e[j], e[i] }
func (e ByDate) Less(i, j int) bool {
	return e[i].LatestModified.UnixNano() < e[j].LatestModified.UnixNano()
}
