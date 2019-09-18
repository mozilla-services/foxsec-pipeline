package com.mozilla.secops;

/** Geo math utilities */
public class GeoUtil {

  /**
   * haversin(0)
   *
   * <p>Taken from: https://github.com/ameihm0912/geomodel/blob/master/geo.go
   *
   * <p>http://en.wikipedia.org/wiki/Haversine_formula
   *
   * @param theta angle
   * @return Resulting half a versine
   */
  public static Double haversin(Double theta) {
    return Math.pow(Math.sin(theta / 2), 2);
  }

  /**
   * Returns the distance (in kilometers) between two points of a given longitude and latitude
   * relatively accurately (using a spherical approximation of the Earth) through the Haversin
   * Distance Formula for great arc distance on a sphere with accuracy for small distances
   *
   * <p>Taken from: https://github.com/ameihm0912/geomodel/blob/master/geo.go
   *
   * <p>http://en.wikipedia.org/wiki/Haversine_formula
   *
   * @param lat1 Latitude 1
   * @param lon1 Longitude 1
   * @param lat2 Latitude 2
   * @param lon2 Longitude 2
   * @return distance in kilometers between the two points
   */
  public static Double kmBetweenTwoPoints(Double lat1, Double lon1, Double lat2, Double lon2) {
    // Earth radius in Kilometers
    int r = 6378;

    // convert to radians
    double lat1Radian = lat1 * Math.PI / 180;
    double lon1Radian = lon1 * Math.PI / 180;
    double lat2Radian = lat2 * Math.PI / 180;
    double lon2Radian = lon2 * Math.PI / 180;

    double h =
        haversin(lat2Radian - lat1Radian)
            + Math.cos(lat1Radian) * Math.cos(lat2Radian) * haversin(lon2Radian - lon1Radian);

    return 2 * r * Math.asin(Math.sqrt(h));
  }
}
