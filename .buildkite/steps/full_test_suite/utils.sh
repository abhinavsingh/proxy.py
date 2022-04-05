
handle_error() {
  if [[ $? -ne 0 ]]
  then
    echo "$1"
    exit 1
  fi
}
