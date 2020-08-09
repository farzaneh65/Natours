/* eslint-disable */

export const displayMap = locations => {
  mapboxgl.accessToken =
    'pk.eyJ1IjoiZmFyemFuZWg2NSIsImEiOiJja2F3N2w0OGExOGgwMnlwdDl5dGlncW0wIn0.yVCkN06vyBW3Z-Dwy84Lag';
  var map = new mapboxgl.Map({
    container: 'map',
    style: 'mapbox://styles/farzaneh65/ckaw8dhab39kk1ipdt75wucvw',
    scrollZoom: false
    //   center: [-118.133686, 34.106055],
    //   zoom: 10,
    //   interactive: false
  });

  const bounds = new mapboxgl.LngLatBounds();

  locations.forEach(loc => {
    //Create marker
    const el = document.createElement('div');
    el.className = 'marker';

    //Add marker
    new mapboxgl.Marker({
      element: el,
      anchor: 'bottom'
    })
      .setLngLat(loc.coordinates)
      .addTo(map);
    //Add popup
    new mapboxgl.Popup({
      offset: 30
    })
      .setLngLat(loc.coordinates)
      .setHTML(`<p>Day ${loc.day}: ${loc.description}</p>`)
      .addTo(map);

    //Extend map bounds to include current location
    bounds.extend(loc.coordinates);
  });

  map.fitBounds(bounds, {
    padding: {
      top: 200,
      bottom: 150,
      left: 100,
      right: 100
    }
  });
};
