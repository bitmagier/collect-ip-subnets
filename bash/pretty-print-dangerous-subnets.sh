for net in $(./collect-dangerous-subnets.sh); do
    ip=$(echo -n $net|sed -e 's/\/[0-9]\{1,2\}$//g')
    country=$(geoiplookup $ip|sed "s/GeoIP Country Edition: //g")
    echo "$net => $country"
done
