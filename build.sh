
#!/bin/bash






main(){
	dir="sphlib-master"
	if [ -d $dir ] 
	then
		return 0;
	fi;

	cat <<EOF
Extracting archive...
EOF

	archive="sphlib-master.zip"
	target_dir=$dir/c
	echo "Extracting archive."
	unzip  -q $archive

	echo "Building sphlib."
	$target_dir/build.sh

	echo "creating symlinks..."
	ln -s "$target_dir" "sphlib"
	echo "Building binary."
	make build

}

main


