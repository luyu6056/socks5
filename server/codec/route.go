package codec

var Control_func = make(map[string]func(*Context))

func Route(route string, f func(*Context)) {
	Control_func[route] = f
}
