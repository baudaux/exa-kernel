for D in *; do
    if [ -d "${D}" ] && [ "$D" != "common" ] && [ "$D" != "include" ]; then
        cd "${D}"
	./build.sh "$@"
	cd ..
    fi
done
